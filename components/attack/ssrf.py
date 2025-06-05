from components.attack.base_attack import BaseAttack
from components.web.request import Request
from components.main.console import log_vulnerability, log_detail, status_update
import components.main.report as report

import uuid


class SSRF(BaseAttack):
    name = 'ssrf'

    CALLBACK_BASE = 'https://webhook.site/c2c35ace-3ad1-4b0e-8a54-d615a14905ee'
    MAGIC_STRING = 'ssrf stahlta scanner'

    SSRF_PARAM_NAMES = [
        'url', 'uri', 'path', 'target', 'dest', 'redirect', 'link',
        'img', 'image', 'file', 'site', 'page', 'host', 'next',
        'callback', 'webhook', 'service', 'endpoint', 'fetch', 'fetchUrl',
        'fetchUrl', 'fetch_url', 'fetch-url', 'proxy', 'proxyUrl',
    ]

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)

    async def run(self, request: Request, response):
        
        status_update(request.url)
        all_params = {**request.get_params, **request.post_params}

        for param in all_params:
            if any(p in param.lower() for p in self.SSRF_PARAM_NAMES):
                unique_id = str(uuid.uuid4())[:8]
                payload_url = f"{self.CALLBACK_BASE}/ssrf-{unique_id}"

                for mutated, p in self.mutate_request(request, payload_url, mode='replace', parameter=param):
                    try:
                        resp = await self.crawler.send(mutated, timeout=3)
                    except Exception:
                        continue

                    if self.MAGIC_STRING in resp.text.lower():
                        log_vulnerability("CRITICAL", "SSRF Detected via reflected content")
                        log_detail("Target", mutated.url)
                        log_detail("Parameter", param)
                        log_detail("Payload", payload_url)
                        log_detail('')

                        report.report_vulnerability(
                            severity="CRITICAL",
                            category="SSRF",
                            description="SSRF vulnerability confirmed via reflected magic string",
                            details={
                                "Target": mutated.url,
                                "Parameter": param,
                                "Payload": payload_url
                            }
                        )
                        return 
