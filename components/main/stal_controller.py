import asyncio
from collections import deque
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse, urlunparse
from playwright.async_api import async_playwright

from components.main.logger import logger
from components.web.request import Request
from components.web.crawler import CrawlerConfig, Crawler
from components.web.explorer import Explorer
from components.web.scope import Scope

from components.attack.base_attack import modules_all, BaseAttack

class Stahlta:
    '''
    Controller for Stahlta. THis class handles the options from the command line and sets the modules to be used.
    '''

    def __init__(self, base_request : Request, scope):
        
        self._base_request : Request = base_request
        self._scope = Scope(base_request= self._base_request, scope= scope)
        
        self._urls = []
        self._forms = []
        
        self._start_urls = deque([self._base_request])
        self._robot_urls = []
        
        self._headless = None
        self._browser = None
        self.p = None
        self._max_depth = 30
        self._timeout = 10
        self._attack_list = []
        
        self._resources  = []
    

    def get_robot_urls(self):

        parser = RobotFileParser(url=f'{self._base_request.scheme}://{self._base_request.netloc}/robots.txt')
        parser.read()

        if parser.disallow_all:
            self._robot_urls = [f"{self._base_request.scheme}://{self._base_request.netloc}/"]

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

        self._robot_urls = disallowed

    async def save_resources(self, explorer):
        
        async for request, response in explorer.async_explore(self._start_urls):
            self._resources.append((request,response))
            
    async def iter_resources(self):
        for request, response in self._resources:
            yield request, response
    
    async def browse(self, stop_event : asyncio.Event, parallelism = 10):
        
        stop_event.clear()
        self._start_urls = deque([ self._base_request ])
        self.get_robot_urls()
        
        logger.info(f'Headless mode activated: {self._headless.title()}')
        
        context = None
        if self._headless == 'yes':
            try:
                context = await self._browser.new_context()
                self._crawler_config = CrawlerConfig(self._base_request, context = context)
                explorer = Explorer(self._crawler_config, self._scope, stop_event, robot_urls = self._robot_urls, parallelism = parallelism)
                
            except Exception as e:
                logger.error(f"Error initializing headless context: {e}")
                return
        else:    
            self._crawler_config = CrawlerConfig(self._base_request)
            explorer = Explorer(self._crawler_config, self._scope, stop_event, robot_urls = self._robot_urls, parallelism = parallelism)
            
        explorer.max_depth = self._max_depth
        explorer.timeout = self._timeout

        try:
            await asyncio.wait_for(self.save_resources(explorer), None)
        finally:
            await explorer.clean()
            if context:
                await context.close()
    
            #[print(response.status_code) for request, response in self._resources]
        
    async def run_attack(self, attack_obj):
        
        async for request, response in self.iter_resources():
            try:
                await attack_obj.run(request, response)
                
            except Exception as e:
                logger.error(f"Error running attack {attack_obj.name}: {e}")
                continue
    
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

        
        async with Crawler.client(self._crawler_config) as crawler:
            
            instances = [cls(crawler, self._crawler_config) for cls in attack_classes]

            for attack_obj in instances:
                
                logger.info(f"Running attack: {attack_obj.name} \n")
                task = asyncio.create_task(self.run_attack(attack_obj))
                try:
                    await task
                    
                except Exception as e:
                    logger.error(f"Error running attack {attack_obj.name}: {e}")
                    continue
    
    async def init_browser(self):
        try:
            self.p = await async_playwright().start()
            self._browser = await self.p.chromium.launch(headless=True,  args=[ "--lang=en-US", "--disable-blink-features=AutomationControlled"])
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
        
    def timeout(self, timeout : int):
        self._timeout = timeout
        
    