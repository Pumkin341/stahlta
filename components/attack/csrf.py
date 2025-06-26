from collections import Counter
from math import log
from httpx import RequestError

from components.attack.base_attack import BaseAttack
from components.web.request import Request
from components.main.console import log_vulnerability, log_detail, status_update
import components.main.report as report


class CSRF(BaseAttack):
    name = 'csrf'

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)
   
        self.CSRF_TOKENS_PARAMS = ['csrfmiddlewaretoken', 'csrfmiddleware', 'authenticity_token', 'authenticity', '__RequestVerificationToken', '__RequestVerification_Token', 
            '__requestverificationtoken', '_token', '_csrf', 'XSRF-TOKEN', 'xsrf-token', 'csrf_token', 'csrf_token_value', 'csrf-protection-token', 
            'csrf_protection_token', 'csrf_magic', 'csrf_magic_token', 'csrf', 'token', 'verifier', 'form_token', 'form_token_value', 'anti_csrf', 
            'anti_csrf_token', 'antiCsrfToken', 'owasp_csrf_token', 'sec-csrf-token', 'nonce', 'session_token', 'csrf_proof_token', 'srf_token', 'crumb',
            'authenticityToken', 'csrfToken', 'user_token', 'user_token_value', 'csrfTokenValue', 'csrfTokenHeader', 'csrfTokenParam']

        self.CSRF_TOKENS_HEADERS = ['X-CSRF-Token', 'X-CSRFToken', 'X-CSRF', 'X-XSRF-TOKEN', 'X-XSRF', 'X-XSRFToken', 'Csrf-Token', 'Csrf', 
            'X-Authenticity-Token', 'X-Authenticity', 'RequestVerificationToken', 'X-RequestVerificationToken', 'XSRF-TOKEN', 
            'anti_csrf', 'anti_csrf_token', 'X-Anti-CSRF-Token', 'X-AntiCsrfToken', 'X-Security-Token', 'X-Form-Token', 'X-Auth-Token', 
            'X-CSRFTOKEN', 'Xsrf-Token-Header', 'Csrf-Token-Header', 'Sec-Csrf-Token', 'CSRF-TOKEN-HEADER', 'X-CSRF-TOKEN-HEADER']

        self.s = lambda i : - sum(f * log(f, 2) for f in ((j / len(i)) for j in Counter(i).values()))
        
    async def run(self, request, response):
        if request.method != 'POST':
            return
        if request.enctype == 'application/json':
            return
        
        status_update(request.url)
        csrf_key, csrf_value = self.look_for_csrf_tokens(request, response)
        
        if not csrf_value:
            vulnerability = 'There is no Anti-CSRF token'
        elif not await self.server_checks_csrf(request, response, csrf_key):
            vulnerability = 'CSRF Token is not checked on the server side'
        elif len(csrf_value) < 8 or self.s(csrf_value) < 3.0:
            vulnerability = f'Anti-CSRF token is too short or not random enough resulting in predictablity {self.s(csrf_value)}'
        else:
            return
        
        details = {
            'Target': request.url,
            'Method': request.method,
            'Form': request.post_params,
        }
        
        log_vulnerability('LOW', vulnerability)
        log_detail('Target', request.url)
        log_detail('Method', request.method)
        log_detail('Form', request.post_params)
        if csrf_key:
            log_detail('CSRF Key', csrf_key)
            log_detail('CSRF Value', csrf_value)
            
            details['CSRF Key'] = csrf_key
            details['CSRF Value'] = csrf_value
        print()
            
        report.report_vulnerability(
            severity='LOW',
            category='CSRF',
            description=vulnerability,
            details= details
        )
        
    async def server_checks_csrf(self, request, response, csrf_key):
        
        new_post_params = {}
        for param, value in request.post_params.items():
            if param == csrf_key:
                new_post_params.update({param: 'invalid_value'})
            else:
                new_post_params.update({param: value})
        
        new_headers = {}
        if response.headers and csrf_key in response.headers:
            new_headers.update({csrf_key: 'invalid_value'})
            
        mutated = Request(
            url=request.url,
            method=request.method,
            get_params=request.get_params,
            post_params=new_post_params,
            file_params=request.file_params,
            depth=request.depth,
            referer=request.referer
        )
        
        try:
            response = await self.crawler.send(request, redirect= True)
        except RequestError:
            return True
        
        try:
            mutated_response = await self.crawler.send(mutated, headers=new_headers, redirect= True)
        except RequestError:
            pass
        
        if response.status_code != mutated_response.status_code:
            return False
        
        return True
        
    def look_for_csrf_tokens(self, request, response):
        for param, value in request.post_params.items():
            if param in self.CSRF_TOKENS_PARAMS:
                return param, value
        
        for header_name, header_value in response.headers.items():
            if header_name.lower() in [h.lower() for h in self.CSRF_TOKENS_HEADERS]:
                return (header_name, header_value)
        
        return None, None