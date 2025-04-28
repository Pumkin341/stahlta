import asyncio
import httpx
from playwright import async_api as playwright
from collections import deque
from typing import Deque
from urllib.parse import urljoin

from components.main.logger import logger

from components.web.request import Request
from components.web.scope import Scope
from components.web.crawler import CrawlerConfig, Crawler
from components.web import EXCLUDED_EXTENSIONS

from components.parsers.html import HTML
from components.parsers.dynamic import js_redirections, dynamic_links

class HeadlessExplorer:
    def __init__(self, crawler_config : CrawlerConfig, scope : Scope, stop_event : asyncio.Event, robot_urls : list,  parallelism : int = 10):
        self._scope = scope
        
        self._stop_event = stop_event
        self._cookiejar = None
        self._max_depth = 30
        self._timeout = 10
        
        self._parallelism = parallelism
        self._semaphore = asyncio.Semaphore(parallelism)
        
        self._hostnames = set()
        self._processed_requests = []
        self._robot_urls = robot_urls
        
        self._client = Crawler.client(crawler_config)
        
    def extract_links(self, response : playwright.Response, request : Request, content : str ):
        
        javascript_links = []
        allowed_links = []
        
        new_requests = []
        
        headers = response.headers
        response_type = headers.get('content-type', '').lower()
        
        js_types = ['/x-javascript', '/javascript', '/x-js']   
        for js_type in js_types: 
            if js_type in response_type:
                javascript_links.extend(js_redirections(content))
                javascript_links.extend(dynamic_links(content, str(response.url)))
                
        if response_type.startswith('text/') or response_type.startswith('application/xml'):
            
            html = HTML(content, str(response.url))
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
                    
            if html.find_login_form()[0] != None:
                print(f"Found a login form at {response.url}")
                print(f"Form: {html.find_login_form()}")
                    
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
        
    async def async_analyze(self, request : Request):
        
        async with self._semaphore:
                
            self._processed_requests.append(request)
            self._hostnames.add(request.hostname)
            
            logger.info(f"Request {request.url:<80} Method {request.method:<5} Depth {request.depth:<5}")
            
            context = None
            page = None
            
            try:
                context = await self._browser.new_context(
                    user_agent= self._crawler._client.headers["User-Agent"],
                    locale= "en-US",
                    extra_http_headers={
                        "Accept": self._crawler._client.headers["Accept"],
                        "Accept-Language": self._crawler._client.headers["Accept-Language"],
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1"
                    }
                )

                page = await context.new_page()
                response = await page.goto(request.url, wait_until="networkidle")
                content = await page.content()
                    
            except asyncio.CancelledError:
                if page:
                    await page.close()
                if context:
                    await context.close()
                raise
            
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error(e)
                if page:
                    await page.close()
                if context:
                    await context.close()
                return False, [], None
                    
            await page.close()
            await context.close()
        
            raw_headers = dict(response.headers)
            raw_headers.pop('content-encoding', None)
            raw_headers.pop('Content-Encoding', None)
            body = content.encode(request.encoding)
            raw_headers['Content-Length'] = str(len(body))

            httpx_req = self._crawler._client.build_request(
                request.method,
                request.url,
                params=request.get_params,
                data=request.post_params
            )
            httpx_resp = httpx.Response(
                status_code=response.status,
                headers=raw_headers,
                content=body,
                request=httpx_req
            )
            
            if request.depth == self._max_depth:
                return True, [], httpx_resp
            
            await asyncio.sleep(0.01)
            links = self.extract_links(response, request, content)
            return True, links, httpx_resp
   
    
    async def async_explore(self, to_explore : Deque[Request]):
        task_request_dict = {}
        
        while True:
            while to_explore:
                if self._stop_event.is_set():
                    break
                
                request = to_explore.popleft()
                if request in self._processed_requests or not self._is_allowed(request.url):
                    continue
                
                if request.depth > self._max_depth:
                    continue
                
                task = asyncio.create_task(self.async_analyze(request))
                task_request_dict[task] = request
                
            if self._stop_event.is_set():
                tasks = list(task_request_dict.keys())
                for t in tasks:
                    t.cancel()
                    
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                break
            
            if task_request_dict:
                done, pending = await asyncio.wait(task_request_dict, timeout=0.25, return_when=asyncio.FIRST_COMPLETED)
            else:
                done = set()
                
            for task in done:
                request = task_request_dict[task]
                
                try:
                    success, links, response = await task
                except Exception as e:
                    logger.error(e)
                else:
                    if success:
                        yield request, response
                    
                    for unprocessed_request in links:
                        if not self._scope.check(unprocessed_request):
                            continue

                        if unprocessed_request.hostname not in self._hostnames:
                            unprocessed_request.depth = 0

                        if unprocessed_request not in self._processed_requests and unprocessed_request not in to_explore:
                            to_explore.append(unprocessed_request)
                            
                del task_request_dict[task]
            
            if not task_request_dict and not to_explore:
                break
    
    def _is_allowed(self, url: str) -> bool:
        return not any(url.startswith(dis) for dis in self._robot_urls)
    
    async def clean(self):
        await self._browser.close()

    @property
    def max_depth(self):
        return self._max_depth
    @max_depth.setter
    def max_depth(self, depth : int):
        self._max_depth = depth
        
    @property
    def timeout(self):
        return self._timeout
    @timeout.setter
    def timeout(self, timeout : int):
        self._timeout = timeout