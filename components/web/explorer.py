import asyncio
import httpx
from typing import Deque
from urllib.parse import urljoin

from components.web.request import Request
from components.web.scope import Scope
from components.web.crawler import CrawlerConfig, Crawler

from components.parsers.html import HTML
from components.parsers.dynamic import js_redirections, dynamic_links

from components.main.logger import logger

from components.web import EXCLUDED_EXTENSIONS

class Explorer:
    
    def __init__(self, crawler_config : CrawlerConfig, scope : Scope, stop_event : asyncio.Event, bad_urls : list, parallelism : int= 5):
        
        self._crawler = Crawler.client(crawler_config)
        self._scope = scope
        self._stop_event = stop_event
        self._semaphore = asyncio.Semaphore(parallelism)
        
        self._max_depth = 30
        self._max_pagesize = 3000000
        self._cookies = {}
        self._hostnames = set()
        
        self._processed_requests = set()
        self._bad_urls = bad_urls
        
    
    def extract_links(self, response : httpx.Response, request):
        
        javascript_links = []
        allowed_links = []
        
        new_requests = []

        
        if response.is_redirect:
            if 'location' in response.headers:
                redirect_url = urljoin(str(response.url), response.headers['location'])
            
        if response.is_redirect and self._scope.check(redirect_url):
            allowed_links.append(redirect_url)
           
        response_type = response.headers.get('content-type', '').lower()
        js_types = ['/x-javascript', '/javascript', '/x-js']   
        for js_type in js_types: 
            if js_type in response_type:
                javascript_links.extend(js_redirections(response.text))
                javascript_links.extend(dynamic_links(response.text, str(response.url)))
                
            
        if response_type.startswith('text/') or response_type.startswith('application/xml'):
            
            html = HTML(response.text, str(response.url))
            allowed_links.extend(self._scope.filter(html.links))    
            allowed_links.extend(self._scope.filter(html.js_redirections + html.html_redirections))
     
            for extra_url in self._scope.filter(html.extra_urls):
                allowed_links.append(extra_url)
                
            for form in html.forms_iterator():
                if self._scope.check(form):
   
                    if form.hostname not in self._hostnames:
                        form.depth = 0
                    else:
                        form.depth = request.depth + 1
                        
                    new_requests.append(form)
                    
            # if html.find_login_form()[0] != None:
            #     print(f" [+] Found a login form at {response.url}")
            #     print(f" [+] Form: {html.find_login_form()}")
                    
        for url in javascript_links:
            if url:
                url = urljoin(str(response.url), url)
                if self._scope.check(url) and url:
                    allowed_links.append(url)
                    
        for new_url in allowed_links:
            if "?" in new_url:
                path_only = new_url.split("?")[0]
                if path_only not in allowed_links and self._scope.check(path_only):
                    allowed_links.append(path_only)
                    
        for new_url in set(allowed_links):
            if not new_url or new_url.endswith(EXCLUDED_EXTENSIONS):
                continue

            if not self._scope.check(new_url) or not self._is_allowed(new_url):
                continue

            depth = request.depth + 1
            new_requests.append(Request(new_url, depth=depth))

        return new_requests

    
    async def _async_analyze(self, request : Request):
        
        async with self._semaphore:
            self._processed_requests.add(request)
            self._hostnames.add(request.hostname)
            
            #logger.info(f"Request {request.url:<80} Method {request.method:<5} Depth {request.depth:<5}")
            logger.debug(request)

            try:
                response = await self._crawler.send(request)
            
            except Exception as e:
                logger.error(e)
                return False, [], None
            
            except (ConnectionError, httpx.RequestError) as e:
                logger.error(e)
                return False, [], None
            
            try:
                await response.aread()
            finally:
                await response.aclose()
                
            if request.depth == self._max_depth:
                return True, [], response
                
            await asyncio.sleep(0.01)
            links = self.extract_links(response, request)
            
            return True, links, response    
        
    async def async_explore(self, to_explore: Deque[Request]):
            task_request_dict: dict[asyncio.Task, Request] = {}

            try:
                while True:
                    
                    while to_explore and not self._stop_event.is_set():
                        req = to_explore.popleft()
                        if req in self._processed_requests or not self._is_allowed(req.url):
                            continue
                        if req.depth > self._max_depth:
                            continue

                        self._processed_requests.add(req)
                        task = asyncio.create_task(self._async_analyze(req))
                        task_request_dict[task] = req

                    if self._stop_event.is_set():
                        for t in list(task_request_dict):
                            t.cancel()
                        break

                    if not task_request_dict and not to_explore:
                        break

                    done, _ = await asyncio.wait( task_request_dict, timeout=0.25, return_when=asyncio.FIRST_COMPLETED)

                    for t in done:
                        req = task_request_dict.pop(t)
                        try:
                            success, links, response = await t
                        except asyncio.CancelledError:
                            continue
                        except Exception as e:
                            logger.error(e)
                            continue

                        if success:
                            yield req, response

                        for new_req in links:
                            if not self._scope.check(new_req) or not self._is_allowed(new_req.url):
                                continue
                            if new_req.hostname not in self._hostnames:
                                new_req.depth = 0
                            if new_req not in self._processed_requests and new_req not in to_explore:
                                to_explore.append(new_req)

            finally:
                for t in task_request_dict:
                    t.cancel()
    
    def _is_allowed(self, url: str) -> bool:
        return not any(url.startswith(dis) for dis in self._bad_urls)
            
    async def clean(self):
        self._cookiejar = self._crawler.cookie_jar
        await self._crawler.close()

    @property
    def cookie_jar(self):
        return self._cookiejar
       
    @property    
    def max_depth(self):
        return self._max_depth
    
    @max_depth.setter
    def max_depth(self, depth : int):
        self._max_depth = depth
        
    @property
    def max_page_size(self):
        return self._max_pagesize
    
    @max_page_size.setter
    def max_page_size(self, size : int):
        self._max_pagesize = size