
import importlib
from components.main.logger import logger

modules_all = ['all', 'sqli', 'xss', 'csrf', 'xxe']

class BaseAttack:
    name: str = None
    
    def __init__(self, crawler, crawler_config):
        self.crawler = crawler
        self.crawler_config = crawler_config
        

    async def run(self, request, response):
        raise NotImplementedError()

    @classmethod
    def load_attacks(cls):
        """
        Dynamically import each attack module named in modules_all (skipping 'all'),
        find its BaseAttack subclass, and return a mapping:
            { 'sqli': SQLiClass, 'xss': XSSClass, … }
        """
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
