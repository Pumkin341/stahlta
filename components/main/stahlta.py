import asyncio
import sys
import signal
from urllib.parse import urlparse

from components.main.logger import logger
from components.main.stal_controller import Stahlta
from components.web.request import Request
from components.attack.base_attack import modules_all
from components.parsers.cli import parse_cli

stop_event = asyncio.Event()

def add_slash_to_path(url : str):
    return url if urlparse(url).path else url + '/'

def ctrl_c():
    print('\n')
    logger.info('Stopping the scan...')
    stop_event.set()
    
def validate_url_endpoint(url: str):
    
    try:
        parts = urlparse(url)
        
    except ValueError as e:
        logger.error('valueError')
        return False
    else:
        if not parts.scheme or not parts.netloc:
            logger.error("Invalid base URL was specified, please give a complete URL with protocol scheme.")
            return False
            
        if parts.scheme in ['http', 'https'] and parts.netloc:
            return True
        
        if parts.params or parts.fragment or parts.query:
            logger.error('The URL should not contain any parameters, fragments, or queries.')
            return False
    
    logger.error('Error: The URL is not valid.')
    return False
        
def printBanner():
    
    banner = r'''
    
   ▄▄▄▄▄      ▄▄▄▄▀ ██    ▄  █ █      ▄▄▄▄▀ ██   
  █     ▀▄ ▀▀▀ █    █ █  █   █ █   ▀▀▀ █    █ █  
▄  ▀▀▀▀▄       █    █▄▄█ ██▀▀█ █       █    █▄▄█ 
 ▀▄▄▄▄▀       █     █  █ █   █ ███▄   █     █  █ 
             ▀         █    █      ▀ ▀         █ 
                      █    ▀                  █  
                     ▀                       ▀   

    '''

    
    print(banner)
    

async def stahlta_main():

    printBanner()
    args = parse_cli()

        
    url = add_slash_to_path(args.url)
    if not validate_url_endpoint(url):
        sys.exit(1)
        
    if args.attacks:
        print('Available attacks: ')
        for module in modules_all:
            print(module)
        sys.exit(0)
        
    if not args.data:
        base_request = Request(url)
    else:
        base_request = Request(url, method = 'POST', post_params = args.data)
        
    stal = Stahlta(base_request, scope= args.scope)
    stal.max_depth = args.depth
    stal.timeout = args.timeout
    stal.attack_list = args.attack
    stal.headless = args.headless
    
    loop = asyncio.get_running_loop()
    
    try:
        loop.add_signal_handler(signal.SIGINT, ctrl_c)
    except NotImplementedError:
        pass

    try:
        if args.headless == 'yes':
            await stal.init_browser()
            
        await stal.browse(stop_event)
        
        if stop_event.is_set():
            logger.info("Scan aborted by user.")
            await stal.close_browser()
            return
        
        logger.info(f"Scan completed, found {stal.count_resources()} resources. \n")
        
        #await stal.attack()
        await stal.close_browser()
    finally:
        try:
            loop.remove_signal_handler(signal.SIGINT)
        except NotImplementedError:
            pass
       

def stahlta_asyncio_run():
    asyncio.run(stahlta_main())
    
    