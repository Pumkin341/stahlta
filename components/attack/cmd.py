import asyncio
import html
import re
import time
from configparser import ConfigParser
from pathlib import Path

from httpx import ReadTimeout, RequestError

import components.main.report as report
from components.main.console import log_vulnerability, log_detail, status_update
from components.attack.base_attack import BaseAttack
from components.web.request import Request

class CommandInjection(BaseAttack):
    name = 'cmd'
    
    WARNING_PATTERNS = [
        r'Warning: exec\(', r'Warning: system\(', r'Warning: shell_exec\(',
        r'Traceback \(most recent call last\):', r'(^|\s)sh: ', r'(^|\s)bash: ', r'cmd not found',
    ]

    def __init__(self, crawler, crawler_config=None, wordlist_path=None):
        super().__init__(crawler, crawler_config, wordlist_path)
        self.semaphore = asyncio.Semaphore(10)
        self.false_positive_timeouts = set()
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        cfg = ConfigParser()
        ini_path = Path(__file__).parent.parent / 'payloads' / 'cmd_injection.ini'
        cfg.read(ini_path)
        payloads = []
        for section in cfg.sections():
            if section.upper() == 'DEFAULT':
                continue
            sec = cfg[section]
            payload = sec.get('payload', '').strip()
            rules = []
            for line in sec.get('rules', '').splitlines():
                tag = line.strip()
                if not tag:
                    continue
                rules.append(html.unescape(tag.replace('[SPACE]', ' ')))
            desc = sec.get('description', section)
            ptype = sec.get('type', 'pattern').strip()
            timeout = sec.getint('timeout', 5) if ptype == 'time' else None
            payloads.append({
                'payload': payload,
                'rules': rules,
                'description': desc,
                'type': ptype,
                'timeout': timeout,
            })
        return payloads

    async def run(self, mutated: Request, response):
        status_update(mutated.url)
        if not mutated.get_params and not mutated.post_params:
            return

        tasks = []
        for entry in self.payloads:
            for mutated_req, param in self.mutate_request(mutated, entry['payload'], mode='append'):
                tasks.append(asyncio.create_task(self._test_payload(mutated_req, response, param, entry)))

        try:
            for task in asyncio.as_completed(tasks):
                if await task:
                    for t in tasks:
                        t.cancel()
                    return
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

    async def _test_payload(self, mutated: Request, original_response, param: str, entry: dict):
        """Test a single payload entry using time, pattern, and warning oracles"""
        ptype = entry.get('type', 'pattern')
        payload = entry['payload']
        desc = entry['description']
        rules = entry['rules']
        
        baseline = original_response.elapsed.total_seconds() 

        # 1) Time-based (blind) injection
        if ptype == 'time':
            
            try:
                time_response = await self.crawler.send(mutated, timeout=5 + baseline + 2)
            
            except (ReadTimeout, RequestError) as e:
                return False
            
            if time_response.status_code != original_response.status_code:
                return False
            
            elapsed = time_response.elapsed.total_seconds()
            if elapsed >= baseline + 5 and elapsed < baseline + 5 + 2:
                log_vulnerability('HIGH', f'{desc} Detected (Time-based)')
                log_detail('Target', mutated.url)
                log_detail('Method', mutated.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Elapsed Time', elapsed)
                print()
                
                report.report_vulnerability(
                    severity='HIGH',
                    category='Command Injection',
                    description=f'{desc} Detected (Time-based)',
                    details={
                        'Target': mutated.url,
                        'Method': mutated.method,
                        'Parameter': param,
                        'Payload': payload,
                        'Elapsed Time': elapsed
                    }
                )
                return True
            
        
        try:
            mutated_response = await self.crawler.send(mutated, timeout=5)
        except Exception:
            return False
        text = mutated_response.text or ''
        for rule in rules:
            if rule in text:
                log_vulnerability('HIGH', f'{desc} Detected')
                log_detail('Target', mutated.url)
                log_detail('Method', mutated.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Matched Rule', rule)
                log_detail('Status Code', mutated_response.status_code)
                print()
                
                report.report_vulnerability(
                    severity='HIGH',
                    category='Command Injection',
                    description=f'{desc} Detected',
                    details={
                        'Target': mutated.url,
                        'Method': mutated.method,
                        'Parameter': param,
                        'Payload': payload,
                        'Matched Rule': rule,
                        'Status Code': mutated_response.status_code
                    }
                )
                return True

        # 3) Warning-based detection
        for pattern in self.WARNING_PATTERNS:
            if re.search(pattern, text):
                log_vulnerability('HIGH', f'{desc} Warning Detected')
                log_detail('Target', mutated.url)
                log_detail('Method', mutated.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Warning Pattern', pattern)
                log_detail('Status Code', mutated_response.status_code)
                print()
                
                report.report_vulnerability(
                    severity='HIGH',
                    category='Command Injection',
                    description=f'Warning detected: {desc}',
                    details={
                        'Target': mutated.url,
                        'Method': mutated.method,
                        'Parameter': param,
                        'Payload': payload,
                        'Warning Pattern': pattern,
                        'Status Code': mutated_response.status_code
                    }
                )
                return True

        return False
