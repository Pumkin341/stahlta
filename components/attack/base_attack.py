
import importlib
import asyncio
from components.main.logger import logger
import json
import re
import copy
from pathlib import Path
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from components.web.request import Request

modules_all = ['all', 'sqli', 'xss', 'csrf', 'xxe']
cve_file_path = './cves/web_cves_all.json'

class BaseAttack:
    name: str = None
    
    _cves_data = None
    _cve_query_cache = {}
    
    def __init__(self, crawler, crawler_config, wordlist_path):
        self.crawler = crawler
        self.crawler_config = crawler_config
        self.wordlist_path = wordlist_path
        
        self.semaphore = asyncio.Semaphore(10)

    async def run(self, request, response):
        raise NotImplementedError()
    
    def iter_payloads(self, wordlist_path):
        with open(wordlist_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if not line.strip():
                    continue
                if line.startswith('#'):
                    continue
                
                yield line.strip()
    
    @classmethod
    def load_attacks(cls):

        registry = {}
        for attack_name in modules_all:
            key = attack_name.lower()
            if key == 'all':
                continue

            module_path = f"components.attack.{key}"
            try:
                mod = importlib.import_module(module_path)
            except ImportError as e:
                logger.error(f"Failed to import module: {module_path} - {e}")
                continue

            # look for the one BaseAttack subclass in that module
            for obj in mod.__dict__.values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseAttack)
                    and obj is not BaseAttack
                ):
                    registry[key] = obj
                    break

        return registry


    def mutate_request(self, request: Request, payload: str, mode: str = 'append'):
            
        new_url = request.url.split('?', 1)[0]
        for param, vals in request.get_params.items():
            new_get_params = copy.deepcopy(request.get_params)
            orig = vals[0] if isinstance(vals, (list, tuple)) else vals
            if not orig:
                orig = ''
            
            if mode == 'append':
                new_get_params[param] = [orig + payload]
            elif mode == 'replace':
                new_get_params[param] = [payload]
            
            new_qs = urlencode(new_get_params, doseq=True)
            new_url_qs = f"{new_url}?{new_qs}"
            
            new_req = Request(
                url=new_url_qs,
                method=request.method,
                depth=request.depth,
                referer=request.referer,
                post_params=request.post_params,
                file_params=request.file_params,
            )
        
            yield new_req, param
            
        for key, vals in request.post_params.items():
            new_req = copy.deepcopy(request)

            if mode == 'append':
                if isinstance(vals, (list, tuple)):
                    new_req.post_params[key] = [v + payload for v in vals]
                else:
                    new_req.post_params[key] = vals + payload
                    
            elif mode == 'replace':
                new_req.post_params[key] = [payload]

            yield new_req, key


    def search_cve(self, query):

        if BaseAttack._cves_data is None:
            cve_path = Path(__file__).parent / cve_file_path
            if not cve_path.exists():
                logger.error(f"CVEs file not found: {cve_path}")
                BaseAttack._cves_data = []
            else:
                with open(cve_path, 'r', encoding='utf-8') as f:
                    BaseAttack._cves_data = json.load(f)

        q = query.lower().strip()
        keywords = sorted(set(re.findall(r'\w+', q)))
        if not keywords:
            return None

        cache_key = (tuple(keywords), q)
        if cache_key in BaseAttack._cve_query_cache:
            return BaseAttack._cve_query_cache[cache_key]

        scored = []
        for cve in BaseAttack._cves_data:
            desc = cve.get('description', '').lower()
            if not any(kw in desc for kw in keywords):
                continue

            score = sum(desc.count(kw) for kw in keywords)
            if q in desc:
                score += 5
            scored.append((score, cve))

        if not scored:
            BaseAttack._cve_query_cache[cache_key] = None
            return None

        top_match = max(scored, key=lambda x: x[0])[1]

        BaseAttack._cve_query_cache[cache_key] = top_match
        return top_match