
from components.attack.base_attack import BaseAttack
from components.main.console import log_vulnerability, log_detail, status_update
import components.main.report as report

class CookieFlags(BaseAttack):
    name = 'cookie_flags'
    
    tested_cookies = set()

    async def run(self, request, response):
        
        if request.method == 'POST':
            return
        
        status_update(request.url)
        cookies = self.crawler.cookies.jar
        
        for cookie in cookies:
            if cookie.name in self.tested_cookies:
                continue
            
            if not cookie.secure:
                log_vulnerability('LOW', f'Cookies secure flag is not set')
                log_detail('Target', request.url)
                log_detail('Cookie', cookie.name)
                print()
                
                report.report_vulnerability(
                    severity='LOW',
                    category='Cookie Flags',
                    description='Cookies secure flag is not set',
                    details={
                        'Target': request.url,
                        'Cookie': cookie.name
                    }
                )
                
            if not cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"):
                log_vulnerability('LOW', f'Cookies HttpOnly flag is not set')
                log_detail('Target', request.url)
                log_detail('Cookie', cookie.name)
                print()
                
                report.report_vulnerability(
                    severity='LOW',
                    category='Cookie Flags',
                    description='Cookies HttpOnly flag is not set',
                    details={
                        'Target': request.url,
                        'Cookie': cookie.name
                    }
                )

            if not (cookie.has_nonstandard_attr("samesite") or cookie.has_nonstandard_attr("SameSite")):
                log_vulnerability('LOW', f'Cookies SameSite flag is not set')
                log_detail('Target', request.url)
                log_detail('Cookie', cookie.name)
                print()

                report.report_vulnerability(
                    severity='LOW',
                    category='Cookie Flags',
                    description='Cookies SameSite flag is not set',
                    details={
                        'Target': request.url,
                        'Cookie': cookie.name
                    }
                )
            self.tested_cookies.add(cookie.name)
                