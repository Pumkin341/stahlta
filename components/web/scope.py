
from components.web.request import Request
from components.main.logger import logger
from urllib.parse import urlparse
from tld import get_tld

class Scope:
    def __init__(self, base_request : Request, scope):
        self._scope = scope
        self._base_request = base_request
        
    def check(self, check_url):
        
        checked = None
        
        if isinstance(check_url, Request):
            url = check_url.url
        else:
            url = check_url
        
        if self._scope == "folder":
            checked = url.startswith(self._base_request.path)
        
        elif self._scope == "domain":
            checked = self._base_request.hostname == urlparse(url).hostname
            
        elif self._scope == "subdomain":
            checked = urlparse(url).hostname == self._base_request.hostname
            
        elif self._scope == "page":
            checked = url.split("?")[0] == self._base_request.path
            
        if checked is None:
            checked = url == self._base_request.url
            
        return checked
            
    def filter(self, filter_urls):
        return {url for url in filter_urls if self.check(url)}
            
        