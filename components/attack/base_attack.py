
import importlib
from components.main.logger import logger
import json
import re
from pathlib import Path

modules_all = ['all', 'sqli', 'xss', 'csrf', 'xxe']
cve_file_path = './cves/web_cves_all.json'

class BaseAttack:
    name: str = None
    
    _cves_data = None
    _cve_query_cache = {}
    
    def __init__(self, crawler, crawler_config):
        self.crawler = crawler
        self.crawler_config = crawler_config
        

    async def run(self, request, response):
        raise NotImplementedError()

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
            except ImportError:
                logger.error(f"Failed to import module: {module_path}")
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
    
    def search_cve(self, query):
        # 1) load CVE data once
        if BaseAttack._cves_data is None:
            cve_path = Path(__file__).parent / cve_file_path
            if not cve_path.exists():
                logger.error(f"CVEs file not found: {cve_path}")
                BaseAttack._cves_data = []
            else:
                with open(cve_path, 'r', encoding='utf-8') as f:
                    BaseAttack._cves_data = json.load(f)

        # 2) normalize and tokenize query into keywords
        q = query.lower().strip()
        keywords = sorted(set(re.findall(r'\w+', q)))
        if not keywords:
            return None

        cache_key = (tuple(keywords), q)
        if cache_key in BaseAttack._cve_query_cache:
            return BaseAttack._cve_query_cache[cache_key]

        # 3) collect & score matches
        scored = []
        for cve in BaseAttack._cves_data:
            desc = cve.get('description', '').lower()
            if not any(kw in desc for kw in keywords):
                continue

            # base score = total occurrences of all keywords
            score = sum(desc.count(kw) for kw in keywords)
            # bonus if full phrase appears
            if q in desc:
                score += 5
            scored.append((score, cve))

        if not scored:
            BaseAttack._cve_query_cache[cache_key] = None
            return None

        # 4) pick only the highest‐scoring
        top_match = max(scored, key=lambda x: x[0])[1]

        # 5) cache & return that one dict
        BaseAttack._cve_query_cache[cache_key] = top_match
        return top_match