import argparse
from components.attack.base_attack import modules_all

def parse_attacks(raw):
    items = [i.strip() for i in raw.split(',')]
    for item in items:
        if item not in modules_all:
            raise argparse.ArgumentTypeError(f"Invalid attack: {item}")
    return items

def parse_cli():
    
    parser = argparse.ArgumentParser(description='Stahlta CLI')
    exclusive = parser.add_mutually_exclusive_group(required=True)
    
    exclusive.add_argument('-u', '--url', dest = 'url', help = 'The URL for scanning.', type = str)
    exclusive.add_argument('-A', dest = 'attacks', action='store_true', help='List the existing attacks.')
    
    parser.add_argument('--username', dest = 'username', help = 'The username for the authentication.', type = str)
    parser.add_argument('--password', dest = 'password', help = 'The password for the authentication.', type = str) 
    parser.add_argument('--login_url', dest = 'login_url', help = 'The login URL for the authentication.', type = str)
    
    parser.add_argument('-a', '--attack',dest='attack', help='The attacks to be used (space separated)', nargs='+', choices=modules_all, default=modules_all)
    parser.add_argument('--headless', dest = 'headless', help = 'Run the scanner in headless mode.', default= 'no', choices= ['yes', 'no'])
    parser.add_argument('--scope', '-s', dest = 'scope', default= 'domain', choices= ['domain', 'page', 'folder', 'subdomain', 'parameter'], help = 'Set the scope for the scan.')
    parser.add_argument('-t', '--timeout', dest = 'timeout', default= 10, help = 'Set the timeout for the request.')
    parser.add_argument('-d', '--depth', dest = 'depth', default= 30, type= int, help = 'Set the depth for the crawler.')
    parser.add_argument('-o', '--output', dest = 'output', default= 'reports', help = 'Set the output file for the report.')
    parser.add_argument('-w', '--wordlist', dest = 'wordlist', help = 'Set the wordlist for the attack.')
    
    return parser.parse_args()