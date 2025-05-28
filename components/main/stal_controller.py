import asyncio
import ssl
import time

from urllib.request import urlopen
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse, urlunparse
from urllib.error import URLError

from collections import deque
from playwright.async_api import async_playwright

from components.main.logger import logger
from components.web.request import Request
from components.web.crawler import CrawlerConfig, Crawler, HTTP_Auth
from components.web.explorer import Explorer
from components.web.scope import Scope

from components.attack.base_attack import modules_all, BaseAttack

class Stahlta:
    def __init__(self, base_request : Request, scope):
        
        self._base_request : Request = base_request
        self._scope = Scope(base_request= self._base_request, scope= scope)
        self.crawler_config = CrawlerConfig(self._base_request)
        
        self._urls = []
        self._forms = []
        
        self._start_urls = deque([self._base_request])
        self.bad_urls = []
 
        self._headless = None
        self._browser = None
        self.p = None
        
        self._max_depth = 30
        self._timeout = 5
        self._attack_list = []
        self._wordlist_path = None
        
        self._resources  = []
    

    def get_robot_urls(self):

        parser = RobotFileParser()
        robots_url = f'{self._base_request.scheme}://{self._base_request.netloc}/robots.txt'
        parser.set_url(robots_url)

        try:
            ctx = ssl._create_unverified_context()
            with urlopen(robots_url, context=ctx) as f:
                lines = [line.decode('utf-8', errors='ignore') for line in f.readlines()]
            parser.parse(lines)
            
        except URLError:
            return
            
        except Exception as e:
            logger.warning(f"Could not fetch or parse robots.txt ({robots_url})")
            return
        
        if parser.disallow_all:
            self.bad_urls = [f"{self._base_request.scheme}://{self._base_request.netloc}/"]

        entries = parser.entries[:]
        if parser.default_entry:
            entries.append(parser.default_entry)

        disallowed = []
        for entry in entries:
            if "*" not in entry.useragents:
                continue
            for rule in entry.rulelines:
                if not rule.allowance:
                    path = rule.path or "/"
                    disallowed.append(f"{self._base_request.scheme}://{self._base_request.netloc}{path}")

        self.bad_urls = disallowed

    async def save_resources(self, explorer):
        
        async for request, response in explorer.async_explore(self._start_urls):
            self._resources.append((request,response))
            
    async def iter_resources(self):
        for request, response in self._resources:
            yield request, response
            
    async def test_connection(self):
        
        async with Crawler.client(self.crawler_config) as crawler:
            logger.info(f"Connecting to {self._base_request.url} ...")
            try:
                response = await crawler.send(self._base_request, timeout=self._timeout)
                
            except Exception as e:
                logger.error(f"Cannot connect to the URL {self._base_request.url}: {e}")
                return False
            
        logger.info(f"Connected to {self._base_request.url} with status code {response.status_code}")
        return True
    
    async def browse(self, stop_event : asyncio.Event, parallelism = 15):
        
        stop_event.clear()
        #self.get_robot_urls()
    
        explorer = Explorer(self.crawler_config, self._scope, stop_event, bad_urls = self.bad_urls, parallelism = parallelism)
            
        explorer.max_depth = self._max_depth
        explorer.timeout = self._timeout

        try:
            await self.save_resources(explorer)
        finally:
            await explorer.clean()
            await self.close_browser()
            
        self.crawler_config.context = None
        self.crawler_config.cookies = explorer._cookies
    
        #[print(request, response) for request, response in self._resources]
        
    async def run_attack(self, attack_obj):
        async for request, response in self.iter_resources():
            await attack_obj.run(request, response)
                
            
    
    async def attack(self):
        registry = BaseAttack.load_attacks()
        
        names = [n.lower() for n in self._attack_list]
        if 'all' in names:
            attack_classes = list(registry.values())
            
        else:
            attack_classes = []
            for name in names:
                cls = registry.get(name)
                if cls:
                    attack_classes.append(cls)

        
        async with Crawler.client(self.crawler_config) as crawler:
            
            instances = [cls(crawler, self.crawler_config, self._wordlist_path) for cls in attack_classes]

            for attack_obj in instances:
                
                logger.log('ATTACK', f"Running attack: {attack_obj.name} \n")
                
                task = asyncio.create_task(self.run_attack(attack_obj))
                try:
                    await task
                    print()
                    
                except Exception as e:
                    logger.error(f"Error running attack {attack_obj.name}: {e}")
                    continue
    
    async def init_browser(self):
        try:
            self.p = await async_playwright().start()
            self._browser = await self.p.chromium.launch(headless=True,  args=[ "--lang=en-US", "--disable-blink-features=AutomationControlled"])
            self.crawler_config.context = await self._browser.new_context()
            
        except Exception as e:
            logger.error(f"Error initializing headless browser: {e}")
            return
    
    async def close_browser(self):
        if self._browser:
            await self._browser.close()
            await self.p.stop()
            self._browser = None
  

    def count_resources(self):
        return len(self._resources)
    
    def set_login(self, login_state, cookies, disconnect_urls):
        self.logged_in = login_state
        self.crawler_config.cookies = cookies
        self.bad_urls.extend(disconnect_urls)
        
    def add_start_url(self, start_url):
        if self._scope.check(start_url):
            self._start_urls.append(start_url)
        
 
    @property
    def headless(self):
        return self._headless
    
    @headless.setter
    def headless(self, headless : str):
        self._headless = headless
    
    @property
    def attack_list(self):
        return self._attack_list
    
    @attack_list.setter
    def attack_list(self, attack_list : list):
        self._attack_list = attack_list
    
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
    
    @property
    def wordlist_path(self):
        return self._wordlist_path
    
    @wordlist_path.setter
    def wordlist_path(self, wordlist : str):
        self._wordlist_path = wordlist
        
    