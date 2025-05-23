import asyncio
import sys
import signal
from urllib.parse import urlparse

from components.main.logger import logger
from components.main.stal_controller import Stahlta
from components.web.request import Request
from components.web.login import log_in
from components.attack.base_attack import modules_all
from components.parsers.cli import parse_cli

stop_event = asyncio.Event()

def add_slash_to_path(url : str):
    return url if urlparse(url).path.endswith('/') else url + '/'

def ctrl_c():
    print('\n')
    logger.info('Stopping the scan...')
    stop_event.set()
    
def validate_url_endpoint(url: str):
    
    try:
        parts = urlparse(url)
        
    except ValueError as e:
        logger.error(f'The URL is not valid: {url}', e)
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
        
def validate_wordlist(wordlist: str):
    try:
        with open(wordlist, 'r') as f:
            lines = f.readlines()
            if not lines:
                logger.error('The wordlist is empty.')
                return False

    except FileNotFoundError:
        logger.error(f'The wordlist file {wordlist} was not found.')
        return False
    
    except Exception as e:
        logger.error(e)
        return False
    
    return True

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
        
   
    base_request = Request(url)
    stal = Stahlta(base_request, scope= args.scope)
    
    if args.wordlist:
        if validate_wordlist(args.wordlist):
            stal.wordlist_path = args.wordlist
        else:
            sys.exit(1)
            
    stal.headless = args.headless
    if args.headless == 'yes':
        logger.info(f'Headless mode: {args.headless.title()} \n')
        await stal.init_browser()
            
    if args.login_url:
        if not args.username or not args.password:
            logger.error('Please provide --username and --password for the authentication.')
            sys.exit(1)
            
        if not validate_url_endpoint(args.login_url):
            logger.error('The login URL is not valid.')
            sys.exit(1)
            
        logger.info('Trying to log in...')
        login_state, cookies, start_url, disconnect_urls = await log_in(crawler_config= stal.crawler_config, username = args.username, password = args.password, login_url = args.login_url)
        stal.set_login(login_state, cookies, disconnect_urls)
        
        if start_url:
            stal.add_start_url(start_url)
            
    elif args.username and args.password:
        logger.error('Please provide --login_url for the authentication.')
        sys.exit(1)
        
        
            
    stal.max_depth = args.depth
    stal.timeout = args.timeout
    stal.attack_list = args.attack
    
    loop = asyncio.get_running_loop()
    
    try:
        loop.add_signal_handler(signal.SIGINT, ctrl_c)
    except NotImplementedError:
        pass

    try:
        await stal.browse(stop_event)
        logger.info(f"Scan completed, found {stal.count_resources()} resources. \n")
        await stal.attack()
        
    finally:
        try:
            loop.remove_signal_handler(signal.SIGINT)
        except NotImplementedError:
            pass
       

def stahlta_asyncio_run():
    asyncio.run(stahlta_main())
    
    