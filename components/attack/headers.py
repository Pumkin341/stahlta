from components.attack.base_attack import BaseAttack
from components.main.console import log_vulnerability, log_detail, status_update
import components.main.report as report

class Headers(BaseAttack):
    name = 'headers'

    HEADERS_TO_CHECK = {
        "X-Frame-Options": {
            "expected": ["deny", "sameorigin"],
            "missing": "Missing X-Frame-Options header (Clickjacking risk)",
            "invalid": "Invalid value in X-Frame-Options (Clickjacking risk)"
        },
        "X-Content-Type-Options": {
            "expected": ["nosniff"],
            "missing": "Missing X-Content-Type-Options header (MIME confusion risk)",
            "invalid": "Invalid value in X-Content-Type-Options (MIME confusion risk)"
        },
        "Strict-Transport-Security": {
            "expected": ["max-age="],
            "missing": "Missing Strict-Transport-Security header (no HTTPS enforcement)",
            "invalid": "Invalid value in Strict-Transport-Security header"
        }
    }

    async def run(self, request, response):
        if request.method != "GET" or request.depth > 0:
            return

        status_update(request.url)
        headers = response.headers

        for header, check in self.HEADERS_TO_CHECK.items():
            if header not in headers:
                log_vulnerability('LOW', check["missing"])
                log_detail('Target', request.url)
                log_detail('Missing Header', header)
                print()
                
                report.report_vulnerability(
                    severity='LOW',
                    category='HTTP Headers',
                    description=check["missing"],
                    details={
                        'Target': request.url,
                        'Header': header
                    }
                )
                continue

            header_val = headers[header].lower()
            if not any(expected in header_val for expected in check["expected"]):
                log_vulnerability('LOW', check["invalid"])
                log_detail('Target', request.url)
                log_detail('Header', header)
                log_detail('Value', header_val)
                print()
                
                report.report_vulnerability(
                    severity='LOW',
                    category='HTTP Headers',
                    description=check["invalid"],
                    details={
                        'Target': request.url,
                        'Header': header,
                        'Value': header_val
                    }
                )