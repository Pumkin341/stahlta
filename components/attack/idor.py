import asyncio
from urllib.parse import urlparse, urlunparse

import components.main.report as report
from components.main.console import log_vulnerability, log_detail, status_update
from components.attack.base_attack import BaseAttack
from components.web.request import Request

class IDOR(BaseAttack):
    name = 'idor'

    def __init__(self, crawler, crawler_config=None, wordlist_path=None):
        super().__init__(crawler, crawler_config, wordlist_path)
        # Fixed concurrency limit
        self.semaphore = asyncio.Semaphore(5)
        # Deltas: near, zero, large, edge
        self.deltas = [1, -1, 0, 10, -10, 999999, -999999]
        # Minimum fractional body‐size change
        self.size_threshold = 0.10

    async def run(self, request: Request, response):
        status_update(request.url)
        if request.method.upper() != 'GET':
            return

        orig_status = response.status_code
        orig_body   = getattr(response, 'body', b'')
        orig_len    = len(orig_body)

        # 1) Path‐based IDOR (manual URL mutation)
        parsed = urlparse(request.url)
        segments = parsed.path.strip('/').split('/')
        for idx, seg in enumerate(segments):
            if not seg.isdigit():
                continue

            base_id = int(seg)
            for delta in self.deltas:
                new_id = base_id + delta
                mutated_segs = segments.copy()
                mutated_segs[idx] = str(new_id)
                new_path = '/' + '/'.join(mutated_segs)
                if parsed.path.endswith('/'):
                    new_path += '/'
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, new_path,
                    parsed.params, parsed.query, parsed.fragment
                ))

                mutated_req = Request(
                    url=new_url,
                    method=request.method,
                    get_params=request.get_params,
                    post_params=request.post_params,
                    file_params=request.file_params,
                    depth=request.depth,
                    referer=request.referer,
                    encoding=request.encoding,
                    enctype=request.enctype
                )

                if await self._check_idor(request.url, orig_status, orig_body, orig_len, mutated_req):
                    return

        # 2) Query‐param IDOR via mutate_request
        for name, val in (request.get_params or {}).items():
            if isinstance(val, str) and val.isdigit():
                base_id = int(val)
                for delta in self.deltas:
                    new_val = str(base_id + delta)
                    for mutated_req, _ in self.mutate_request(
                        request, payload=new_val, 
                        mode='replace', parameter=name
                    ):
                        if await self._check_idor(request.url, orig_status, orig_body, orig_len, mutated_req):
                            return

    async def _check_idor(self, orig_url, orig_status, orig_body, orig_len, mutated_req):
        """Send mutated_req, compare, and report if IDOR is found."""
        try:
            async with self.semaphore:
                mutated_resp = await self.crawler.send(mutated_req)
        except Exception:
            return False

        mut_status = getattr(mutated_resp, 'status_code', 0)
        # 1) status flip
        if not (orig_status >= 400 and 200 <= mut_status < 300):
            return False

        # 2) body‐length threshold
        mut_body = getattr(mutated_resp, 'body', b'')
        mut_len  = len(mut_body)
        if orig_len > 0:
            change = abs(mut_len - orig_len) / orig_len
            if change < self.size_threshold:
                return False

        # 3) content diff
        if orig_body == mut_body:
            return False

        # Report!
        log_vulnerability('HIGH', 'Insecure Direct Object Reference detected')
        log_detail('Original URL', orig_url)
        log_detail('Mutated URL', mutated_req.url)
        report.report_vulnerability(
            severity='HIGH',
            category='Broken Access Control',
            description='Insecure Direct Object Reference detected',
            details={
                'Original URL': orig_url,
                'Mutated URL': mutated_req.url,
                'Original Status': orig_status,
                'Mutated Status': mut_status
            }
        )
        return True
