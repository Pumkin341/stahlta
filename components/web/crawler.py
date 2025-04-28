import asyncio
import ssl
import httpx
from dataclasses import dataclass
from http.cookiejar import CookieJar

from playwright.async_api import BrowserContext, Browser
from playwright._impl._errors import TargetClosedError

from components.web.request import Request
from components.main.logger import logger

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"

@dataclass
class HTTP_Auth:
    username : str
    password : str
    method : str = 'basic'

@dataclass
class CrawlerConfig:
    base_request : Request
    context : BrowserContext = None
    timeout : int = 10 
    compression : bool = True
    http_auth : HTTP_Auth = None
    user_agent : str = USER_AGENT
    cookies : CookieJar = None
    headers : dict = None
    secure : bool = True 
    
    
class Crawler:
    def __init__(self, base_request : Request, client : httpx.AsyncClient, context : BrowserContext, timeout : int = 10):
        
        self._base_request = base_request
        self._client = client
        self._context = context
        self._timeout = timeout
        
    
    @classmethod
    def client(cls, config : CrawlerConfig):
        
        headers = {
            "User-Agent" : config.user_agent,
            "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language" : "en-US,en;q=0.5",
            "Accept-Encoding" : "gzip, deflate, br",
            "Connection" : "keep-alive"
        }
        headers.update(config.headers or {})

        if config.compression == False:
            headers['Accept-Encoding'] = "identity"
            
        ssl_ctx = httpx.create_ssl_context() 
        ssl_ctx.check_hostname = config.secure
        if config.secure:
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
        authentification = None
        if config.http_auth:
            if config.http_auth.method == 'basic':
                authentification = httpx.BasicAuth(config.http_auth.username, config.http_auth.password)
            elif config.http_auth.method == 'digest':
                authentification = httpx.DigestAuth(config.http_auth.username, config.http_auth.password)
                
        
        client = httpx.AsyncClient(
            auth= authentification,
            headers = headers,
            timeout = config.timeout,
            cookies = config.cookies,
            verify= ssl_ctx
        )
        
        if config.context:
            context = config.context
            context.set_default_timeout(config.timeout * 1000)
        else:
            context = None
            
        return cls(config.base_request, client, context, config.timeout)
    
    
    async def get(self, base_request : Request, redirect : bool = True, headers : dict = None, timeout : int = None) -> httpx.Response:
        
        # Headless
        page = None
        
        timeout = timeout or self._timeout
        
        if self._context:
            try:
                page = await self._context.new_page()
                if headers:
                    await page.set_extra_http_headers(headers)
                pr = await page.goto(
                    base_request.url,
                    wait_until='domcontentloaded',
                    timeout=timeout * 1000
                )
                content = await page.content()
                
            except asyncio.CancelledError:
                if page is not None:
                    await page.close()
                raise

            except TargetClosedError:
                if page is not None:
                    await page.close()
                raise
            
            except Exception as e:
                if 'net::ERR_ABORTED' in str(e) or 'Protocol error' in str(e):
                    if page is not None:
                        await page.close()
                    raise asyncio.CancelledError()
                logger.error(f'GET on url: {base_request}: {e}')
                raise
            
            finally:
                if page is not None:
                    try:
                        await page.close()
                    except Exception:
                        pass
                
            raw_headers = dict(pr.headers)
            raw_headers.pop("content-encoding", None)
            raw_headers["Content-Length"] = str(len(content))

            httpx_req = self._client.build_request(
                'GET',
                base_request.url,
                headers=headers or {},
                timeout=timeout or self._timeout
            )
            
            return httpx.Response(
                status_code=pr.status,
                headers=raw_headers,
                content=content,
                request=httpx_req
            )
            
        # httpx
        get_request = self._client.build_request('GET', base_request.url, headers=headers, timeout = timeout)
        
        try:
            response = await self._client.send(get_request, follow_redirects = redirect)
            
        except httpx.TransportError as e:
            logger.error(f"GET on url: {self._base_request}: {e}")
            raise e
        
        return response
        
    async def post(self, method : str, base_request : Request, redirect : bool  = False, headers : dict = None, timeout : int = None):
        
        if timeout is None:
            timeout = self._timeout
        else:
            timeout = httpx.Timeout(timeout)
            
        post_request = self._client.build_request(method, base_request.url, params = base_request.get_params, data = base_request.post_params, headers=headers, timeout = timeout)
        
        try:
            response = await self._client.send(post_request, follow_redirects = redirect)

            
        except httpx.TransportError as e:
            logger.error(f"POST on url: {self._base_request}: {e}")
            raise e
        
        return response
    
    async def send(
        self,
        base_request : Request,
        headers : dict = None,
        redirect : bool = True,
        timeout : int = None
    ):
        if base_request.method == 'GET':
            response = await self.get(base_request, headers = headers, redirect = redirect, timeout = timeout)
        else:
            response = await self.post(base_request.method, base_request, headers = headers, redirect = redirect, timeout = timeout)
            
        return response
    
    async def __aenter__(self):
        return self

    async def close(self):
        await self._client.aclose()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False
    

    # Setters and Getters
    @property
    def user_agent(self):
        return self._client.headers['User-Agent']
    
    @property
    def timeout(self):
        return self._timeout.timeout
    
    @property
    def headers(self):
        return self._client.headers
    
    @user_agent.setter
    def user_agent(self, value):
        self._client.headers['User-Agent'] = value
        
    @property
    def cookie_jar(self):
        return self._client.cookies.jar