import re
import difflib
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
        
        if not request.get_params and not request.post_params:
            return
        
        raw = await self._get_text(response)
        self._original_body = html.unescape(unquote(raw)).lower()
        self._baseline = self._original_body.splitlines()

        tasks = []
        for payload in self.iter_payloads(self.wordlist_path):
            for mutated, param in self.mutate_request(request, payload, mode='replace'):
                tasks.append(asyncio.create_task(self.test_xss(mutated, param, payload)))
            
        if not tasks:
            return

        for fut in asyncio.as_completed(tasks):
            try:
                found = await fut
            except asyncio.CancelledError:
                continue
            except Exception as e:
                pass

            if found:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                return 

    async def test_xss(self, mutated: Request, param: str, payload: str) -> bool:
        
        async with self.semaphore:
            try:
                new_resp = await self.crawler.send(mutated, timeout=3)
            except Exception:
                return False

        #logger.debug(mutated)
        ctype = new_resp.headers.get('content-type', '').lower()
        if 'json' in ctype:
            return False

        new_raw = await self._get_text(new_resp)
        new_body = html.unescape(unquote(new_raw)).lower()
        new_lines = new_body.splitlines()

        diff = difflib.ndiff(self._baseline, new_lines)
        injected = [
            line[2:] for line in diff
            if line.startswith('+ ') and 'st4r7s' in line and '3nd' in line
        ]

        found = False
        if injected:
            m = re.search(r'st4r7s(.*?)3nd', injected[0])
            if m:
                snippet = f"st4r7s{m.group(1)}3nd"
                efficiency = fuzz.partial_ratio(snippet, payload.lower())
                found = True
        else:
            # fallback: raw payload unescaped?
            if payload.lower() in new_body:
                snippet = payload.lower()
                efficiency = 100
                found = True

        if not found or efficiency < 30:
            return False

        # 5) Map efficiency → confidence
        if efficiency >= 98:
            confidence = 'CRITICAL'
        elif efficiency >= 90:
            confidence = 'HIGH'
        elif efficiency >= 75:
            confidence = 'MEDIUM'
        elif efficiency >= 50:
            confidence = 'LOW'
        else:
            return False

        # 6) Log exactly as before
        context = self._detect_context(self._original_body, param, payload)
        logger.log(confidence, "XSS Vulnerability Found")
        logger.log("VULN", f"Target:     {mutated.method} {mutated.url}")
        logger.log("VULN", f"Parameter:  {param}")
        logger.log("VULN", f"Payload:    {payload}")
        logger.log("VULN", f"Efficiency: {efficiency}%")
        logger.log("VULN", f"Context:    {context}")
        logger.log("VULN", "")

        return True

    async def _get_text(self, resp):
        try:
            return resp.text
        except AttributeError:
            return resp.content.decode(resp.encoding or 'utf-8', errors='ignore')

    def _detect_context(self, body: str, name: str, orig: str) -> str:
        idx = body.find(orig.lower())

        for m in re.finditer(r'(?is)<script[^>]*>.*?</script>', body):
            if m.start() <= idx <= m.end():
                return 'script'

        attr_re = rf'\b{name}\s*=\s*"[^"]*{re.escape(orig.lower())}[^"]*"'
        if re.search(attr_re, body):
            return 'attribute'

        return 'html'
