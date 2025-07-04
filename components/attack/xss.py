import re
import asyncio
from pathlib import Path
from fuzzywuzzy import fuzz
from icecream import ic
from urllib.parse import unquote

import components.main.report as report
from components.main.console import status_update, log_vulnerability, log_detail, log_error
from components.attack.base_attack import BaseAttack
from components.web.request import Request

from components.attack.xss_utils import csp_blocks_inline, escaped, generate_vectors, check_dom, fill_holes

MARKER = 's74l7a'

class XSS(BaseAttack):
    name = 'xss'

    def __init__(self, crawler, crawler_config, wordlist_path):
        super().__init__(crawler, crawler_config, wordlist_path)
        if not self.wordlist_path:
            self.wordlist_path = (
                Path(__file__).parent.parent 
                / 'payloads' / 'xss' / 'xss_small.txt'
            )

    async def run(self, request: Request, response):
        
        # print(request)
        # print(response.text)
        # print()
        
        status_update(request.url)
        
        if not request.get_params and not request.post_params:
            return
        
        dom = check_dom(response.text)
        if dom:
            log_vulnerability('LOW', 'Potential Reflected DOM-based XSS found:')
            log_detail('Target', request.url)
            log_detail('Explanation', (
                "The following code block is extracted from the page's JavaScript. "
                "Relevant JavaScript sources (where user input may enter the code) and dangerous sinks (functions that can result in code execution) are highlighted for visibility in the report. "
                "If untrusted user input can reach one of these dangerous functions, it may be possible for an attacker to execute JavaScript in the browser (DOM-based XSS). "
                "Review the highlighted code to determine if user-controllable data is passed to functions like document.write, innerHTML, or similar without proper sanitization."
            ))
            print()
            for line in dom:
                if line:
                    log_detail(line)
            print()
            
            details = '\n'.join(dom)
            details = re.sub(r'\x1b\[[0-9;]*m', '', details)
            details = (details.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;"))
            for word in ['document.write', 'innerHTML', 'document.location', 'eval', 'setTimeout']:
                details = details.replace(word, f'<span style="color:#f66;font-weight:bold">{word}</span>')
            pretty_details = f'<pre style="font-size:13px;background:#222;color:#eee;padding:8px;border-radius:6px;overflow-x:auto;"><code>{details}</code></pre>'
            
            report.report_vulnerability(
                'LOW',
                'XSS',
                'Potential DOM-based XSS found',
                {
                    'Target': request.url,
                    'Explanation': (
                        "The following code block is extracted from the page's JavaScript. "
                        "Relevant JavaScript sources (where user input may enter the code) and dangerous sinks (functions that can result in code execution) are highlighted for visibility in the report. "
                        "If untrusted user input can reach one of these dangerous functions, it may be possible for an attacker to execute JavaScript in the browser (DOM-based XSS). "
                        "Review the highlighted code to determine if user-controllable data is passed to functions like document.write, innerHTML, or similar without proper sanitization."
                    ),
                    'HTML_Details': pretty_details,
                }
            )
        
        for mutated, param in self.mutate_request(request, 's74l7a', mode = 'replace'):
            
            try:
                mutated_response = await self.crawler.send(mutated, timeout = 1.5)
            except Exception as e:
                return {}
            
            occurences = await self.detect_context(mutated, mutated_response)
            positions = occurences.keys()
            
            if not occurences:
                continue
           
            #log_debug(f'Reflections found in {param} for {mutated.url}: {len(occurences)}')
            
            efficiencies = await self.filter_checker(request, param, occurences)
            vectors = generate_vectors(occurences, mutated_response.text)
            
            total = 0
            for v in vectors.values():
                total += len(v)
                
            if total == 0:
                continue            
            
            tasks = [
                asyncio.create_task(self.test_xss(mutated, param, vect, confidance, efficiencies, positions))
                for confidance, vects in vectors.items()
                for vect in vects
            ]

            if not tasks:
                continue

            for finished in asyncio.as_completed(tasks):
                try:
                    success = await finished
                except asyncio.CancelledError:
                    continue

                if success:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    break

            await asyncio.sleep(0)               
                
    async def test_xss(self, request: Request, param, vect, confidance, occurences, positions):
        
        log_payload = vect
        # if request.method != 'GET':
        #     vect = unquote(vect)
        
        efficiencies, mutated, mutated_response = await self.checker(request, param, vect, positions)
        status_update(mutated.url)
        # print(log_payload)
        # print(vect)
        # print(occurences)
        # print(positions)
        # print(efficiencies)
        # print()
        
        if not efficiencies:
            for i in range(len(occurences)):
                efficiencies.append(0)

        bestEfficiency = max(efficiencies)

        csp_blocks = csp_blocks_inline(mutated_response.headers)
        
        if (bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95)) and not csp_blocks:
            url = mutated.url.replace('st4r7s', '')
            url = url.replace('3nd', '')
            
            log_vulnerability('CRITICAL', f'Reflected XSS Vulnerability Found')
            log_detail(f'Target', f'{url}')
            log_detail(f'Method', mutated.method)
            log_detail(f'Parameter', param)
            log_detail(f'Payload', log_payload)
            log_detail(f'Efficiency', bestEfficiency)
            log_detail(f'Confidance', confidance)
            log_detail('')
            
            report.report_vulnerability(
                'CRITICAL',
                'XSS',
                'XSS Reflected Vulnerability',
                {
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': log_payload,
                    'Efficiency': bestEfficiency,
                    'Confidance': confidance,
                }
            )
            return True
        

        elif (bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95)) and csp_blocks:
            log_vulnerability('LOW', f'Potential XSS blocked by CSP')
            log_detail(f'Target', mutated.url)
            log_detail(f'Method', mutated.method)
            log_detail(f'Parameter', param)
            log_detail(f'Payload', vect)
            log_detail(f'Efficiency', bestEfficiency)
            log_detail('')
            
            report.report_vulnerability(
                'LOW',
                'XSS',
                'Potential XSS blocked by CSP',
                {
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': vect,
                    'Efficiency': bestEfficiency
                }
            )
            return True

        return False
    
    async def detect_context(self, mutated: Request, mutated_response: Request):


        text = mutated_response.text
        reflections = text.count(MARKER)
        if reflections == 0:
            return {}

        position_and_context = {}
        environment_details = {}

        clean_response = re.sub(r'<!--[.\s\S]*?-->', '', text)
        script_checkable = clean_response
        
        scripts = []
        matches = re.findall(r'(?s)<script.*?>(.*?)</script>', script_checkable.lower())
        for match in matches:
            if MARKER in match:
                scripts.append(match)

        for script in scripts:
            for occ in re.finditer(rf'({MARKER}.*?)$', script, re.MULTILINE):
                pos = occ.start(1)
                position_and_context[pos] = 'script'
                environment_details[pos] = {'details': {'quote': ''}}
                for i, ch in enumerate(occ.group()):
                    if ch in ('/', "'", '`', '"') and not escaped(i, occ.group()):
                        environment_details[pos]['details']['quote'] = ch
                    elif ch in (')', ']', '}', '}') and not escaped(i, occ.group()):
                        break
                script_checkable = script_checkable.replace(MARKER, '', 1)

        if len(position_and_context) < reflections:
            for occ in re.finditer(rf'<[^>]*?({MARKER})[^>]*?>', clean_response):
                part = occ.group(0)
                pos = occ.start(1)
                tag = re.match(r'<\s*([\w-]+)', part)
                tag_name = tag.group(1) if tag else ''
                Type, quote, name, value = '', '', '', ''
                for seg in re.split(r"\s+", part):
                    if MARKER in seg:
                        if '=' in seg:
                            qm = re.search(r'=(["`\'])', seg)
                            quote = qm.group(1) if qm else ''
                            nv = seg.split('=', 1)
                            name = nv[0]
                            value = nv[1].rstrip('>').strip(quote)
                            Type = 'value' if name != MARKER else 'name'
                        else:
                            Type = 'flag'
                position_and_context[pos] = 'attribute'
                environment_details[pos] = {'details': {'tag': tag_name, 'type': Type, 'quote': quote, 'name': name, 'value': value}}

        if len(position_and_context) < reflections:
            for occ in re.finditer(MARKER, clean_response):
                pos = occ.start()
                if pos not in position_and_context:
                    position_and_context[pos] = 'html'
                    environment_details[pos] = {'details': {}}

        if len(position_and_context) < reflections:
            for occ in re.finditer(rf'<!--[.\s\S]*?({MARKER})[.\s\S]*?-->', text):
                pos = occ.start(1)
                position_and_context[pos] = 'comment'
                environment_details[pos] = {'details': {}}

        database = {}
        for pos in sorted(position_and_context):
            database[pos] = {
                'position': pos,
                'context': position_and_context[pos],
                'details': environment_details[pos]['details']
            }

        bad_ctx_iter = re.finditer(rf'(?is)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*?({MARKER})[.\s\S]*?</\1>', text)
        non_exec = []
        for bc in bad_ctx_iter:
            non_exec.append((bc.start(), bc.end(), bc.group(1)))
        if non_exec:
            for key in database:
                
                bad_tag = ''
                for each in non_exec:
                    if each[0] < database[key]['position'] < each[1]:
                        bad_tag = each[2]
                        break

                database[key]['details']['badTag'] = bad_tag or ''

        return database

    async def filter_checker(self, request, param, occurrences):
        positions = occurrences.keys()
        sorted_efficiencies = {}
        payloads = {'<', '>'}

        for i in range(len(positions)):
            sorted_efficiencies[i] = {}

        for i in occurrences:
            occurrences[i]['score'] = {}
            context = occurrences[i]['context']

            if context == 'comment':
                payloads.add('-->')
            elif context == 'script':
                payloads.add(occurrences[i]['details']['quote'])
                payloads.add('</scRipT/>')
            elif context == 'attribute':
                details = occurrences[i]['details']
                if details['type'] == 'value' and details['name'] == 'srcdoc':
                    payloads.add('&lt;')
                    payloads.add('&gt;')
                if details.get('quote'):
                    payloads.add(details['quote'])

        for payload in payloads:
            if not payload:
                continue

            efficiencies, _, _ = await self.checker(request, param, payload, positions)
            efficiencies.extend([0] * (len(occurrences) - len(efficiencies)))

            for occurrence, efficiency in zip(occurrences, efficiencies):
                occurrences[occurrence]['score'][payload] = efficiency

        return occurrences


    async def checker(self, request: Request, param, payload, positions):
        check_string = 'st4r7s' + payload + '3nd'

        for mutated, param in self.mutate_request(request, check_string, mode='replace', parameter=param):
            async with self.semaphore:
                response = await self.crawler.send(mutated, timeout=1.5)

        response_text = response.text

        reflected_positions = [match.start() for match in re.finditer('st4r7s', response_text)]
        filled_positions = fill_holes(positions, reflected_positions)

        efficiencies = []
        num = 0

        for position in filled_positions:
            all_efficiencies = []

            try:
                start_idx = reflected_positions[num]
                reflected = response_text[start_idx: start_idx + len(check_string)]
                efficiency = fuzz.partial_ratio(reflected, check_string.lower())
                all_efficiencies.append(efficiency)
            except (IndexError, UnboundLocalError):
                pass

            if position:
                reflected = response_text[position: position + len(check_string)]
                efficiency = fuzz.partial_ratio(reflected, check_string)
                # Special case for escaped injections
                if reflected[:-2] == f"\\%s" % check_string.replace('st4r7s', '').replace('3nd', ''):
                    efficiency = 90
                all_efficiencies.append(efficiency)

                efficiencies.append(max(all_efficiencies))
            else:
                efficiencies.append(0)

            num += 1

        return list(filter(None, efficiencies)), mutated, response







