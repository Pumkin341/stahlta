import asyncio
import html
import re
import time
from configparser import ConfigParser
from pathlib import Path

from httpx import ReadTimeout, RequestError

from components.main.console import log_vulnerability, log_detail, status_update
from components.attack.base_attack import BaseAttack
from components.web.request import Request

class CommandInjection(BaseAttack):
    name = 'cmd'
    SKIP_PARAMS = {'csrf_token', 'session_id', 'auth_token', 'auth_key', 'token'}

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
            rules = [html.unescape(line.strip().replace('[SPACE]', ' '))
                     for line in sec.get('rules', '').splitlines() if line.strip()]
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

    async def run(self, request: Request, response):
        status_update(request.url)
        if not request.get_params and not request.post_params:
            return
        tasks = []
        for entry in self.payloads:
            for mutated_req, param in self.mutate_request(request, entry['payload'], mode='append'):
                if param in self.SKIP_PARAMS:
                    continue
                tasks.append(asyncio.create_task(self._test_payload(mutated_req, param, entry)))

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

    async def _test_payload(self, req: Request, param: str, entry: dict):
        ptype = entry.get('type', 'pattern')
        payload = entry['payload']
        desc = entry['description']
        rules = entry['rules']
        timeout_threshold = entry.get('timeout', 5)

        # 1) Time-based (blind) injection
        if ptype == 'time':
            if req.url in self.false_positive_timeouts:
                return False
            try:
                # If server does not respond within threshold, ReadTimeout is raised
                await self.crawler.send(req, timeout=timeout_threshold)
            except ReadTimeout:
                log_vulnerability('HIGH', f'Blind Command Execution Detected ({desc})')
                log_detail('Target', req.url)
                log_detail('Method', req.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                return True
            except RequestError:
                return False
            return False

        # 2) Pattern-based detection
        try:
            resp = await self.crawler.send(req, timeout=5)
        except Exception:
            return False
        text = resp.text or ''
        for rule in rules:
            if rule in text:
                log_vulnerability('HIGH', f'Command Execution Detected ({desc})')
                log_detail('Target', req.url)
                log_detail('Method', req.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Matched Rule', rule)
                log_detail('Status Code', resp.status_code)
                return True

        # 3) Warning-based detection
        for pattern in self.WARNING_PATTERNS:
            if re.search(pattern, text):
                log_vulnerability('HIGH', f'Warning Detected ({desc})')
                log_detail('Target', req.url)
                log_detail('Method', req.method)
                log_detail('Parameter', param)
                log_detail('Payload', payload)
                log_detail('Warning Pattern', pattern)
                log_detail('Status Code', resp.status_code)
                return True

        return False
