import argparse
from components.attack.base_attack import modules_all

def parse_attacks(raw):
    items = [i.strip() for i in raw.split(',')]
    for item in items:
        if item not in modules_all:
            raise argparse.ArgumentTypeError(f"Invalid attack: {item}")
    return items

def parse_cli():
    
    parser = argparse.ArgumentParser(description='StahltaCore CLI')
    exclusive = parser.add_mutually_exclusive_group(required=True)
    
    exclusive.add_argument('-u', '--url', dest = 'url', help = 'The URL for scanning.', type = str)
    exclusive.add_argument('-A', dest = 'attacks', action='store_true', help='List the existing attacks.')
    
    parser.add_argument('--headless', dest = 'headless', help = 'Run the scanner in headless mode.', default= 'no', choices= ['yes', 'no'])
    parser.add_argument('-a', '--attack', dest='attack', help='The attacks to be used (comma separated)', type=parse_attacks, default=modules_all, choices=modules_all)
    
    parser.add_argument('--scope', '-s', dest = 'scope', default= 'domain', choices= ['domain', 'page', 'folder', 'subdomain'], help = 'Set the scope for the scan.')
    parser.add_argument('--data', dest = 'data', help = 'Data to be sent with the POST request.')
    parser.add_argument('-t', '--timeout', dest = 'timeout', default= 10, help = 'Set the timeout for the request.')
    parser.add_argument('-d', '--depth', dest = 'depth', default= 30, type= int, help = 'Set the depth for the crawler.')
    parser.add_argument('-o', '--output', dest = 'output', default= 'stahlta_report', help = 'Set the output file for the report.')
    

    
    
    return parser.parse_args()