import re
import difflib
import uuid
import html
import asyncio
from urllib.parse import quote, unquote
from fuzzywuzzy import fuzz
from pathlib import Path

from components.main.logger import logger
from components.attack.base_attack import BaseAttack
from components.web.request import Request

class XSS(BaseAttack):
    name = 'xss'

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)
        if not self.wordlist_path:
            self.wordlist_path = (
                Path(__file__).parent.parent 
                / 'payloads' / 'xss' / 'xss_small.txt'
            )
            
        self._original_body = ''
        self._baseline = []

        self._found_event = None

    async def run(self, request: Request, response):
        # only scan if there are parameters
        if not request.get_params and not request.post_params:
            return

        tasks = []
        for payload in self.iter_payloads(self.wordlist_path):
            # generate unique markers to avoid false positives
            marker = uuid.uuid4().hex[:8]
            left = f"__{marker}__"
            right = f"__{marker[::-1]}__"
            wrapped = f"{left}{payload}{right}"

            for mutated, param in self.mutate_request(request, wrapped, mode='replace'):
                tasks.append(
                    asyncio.create_task(
                        self.test_xss_reflected(mutated, param, payload, left, right)
                    )
                )

        if not tasks:
            return

        # await tasks and cancel on first found
        for fut in asyncio.as_completed(tasks):
            try:
                if await fut:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return
            except asyncio.CancelledError:
                continue
            except Exception:
                continue

    async def test_xss_reflected(self,
                                 mutated: Request,
                                 param: str,
                                 orig_payload: str,
                                 left: str,
                                 right: str) -> bool:
        async with self.semaphore:
            try:
                new_resp = await self.crawler.send(mutated, timeout=5)
            except Exception:
                return False

        ctype = new_resp.headers.get('content-type', '').lower()
        if 'html' not in ctype:
            return False

        # use raw HTML response (without unescaping entities)
        raw = await self._get_text(new_resp)
        body = raw

        # confirm markers present
        if left not in body or right not in body:
            return False

        # extract snippet between markers
        snippet_re = re.escape(left) + r"(.*?)" + re.escape(right)
        match = re.search(snippet_re, body, re.DOTALL)
        if not match:
            return False
        reflected = match.group(1)

        # ensure original payload reflection (raw) is present
        if orig_payload not in reflected:
            return False

        # detect injection context
        context = self._detect_context(body, param, reflected)

        # context-specific sanity checks on RAW snippet
        if context == 'html':
            # require literal HTML tags
            if not re.search(r'<[a-zA-Z/][^>]*>', reflected):
                return False
        elif context == 'attribute':
            # require event handler or attribute-break pattern
            if not re.search(r'on\w+\s*=|"\s*>|>$', reflected):
                return False
        elif context == 'script':
            # require JS keywords or literal <script>
            if not re.search(r'\b(alert|prompt|confirm)\b|<script', reflected):
                return False

        # confirmed reflected XSS
        confidence = 'CRITICAL'
        logger.log(confidence, "Reflected XSS Vulnerability Found")
        logger.log("VULN", f"Target:     {mutated.url}")
        logger.log("VULN", f"Method:     {mutated.method}")
        logger.log("VULN", f"Parameter:  {param}")
        logger.log("VULN", f"Payload:    {orig_payload}")
        logger.log("VULN", f"Context:    {context}")
        logger.log("VULN", "")
        return True

    async def _get_text(self, resp):
        try:
            return resp.text
        except AttributeError:
            return resp.content.decode(
                resp.encoding or 'utf-8', errors='ignore'
            )

    def _detect_context(self, body: str, name: str, snippet: str) -> str:
        idx = body.find(snippet)
        # script context
        for m in re.finditer(r'(?is)<script[^>]*>.*?</script>', body):
            if m.start() <= idx <= m.end():
                return 'script'
        # attribute context
        attr_pattern = rf"<\w+[^>]*\b{name}\s*=\s*['\"][^'\"]*{re.escape(snippet)}[^'\"]*['\"]"
        if re.search(attr_pattern, body, re.IGNORECASE):
            return 'attribute'
        return 'html'
