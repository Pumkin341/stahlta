import re
import asyncio
from pathlib import Path
from fuzzywuzzy import fuzz
from icecream import ic

import components.main.report as report
from components.main.console import status_update, log_vulnerability, log_detail, log_error
from components.attack.base_attack import BaseAttack
from components.web.request import Request

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
        
        dom = self.check_dom(response.text)
        if dom:
            log_vulnerability('LOW', 'Potential Reflected DOM-based XSS found:')
            log_detail('Target', request.url)
            for line in dom:
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
                    'Details': ''
                }
            )
        
        for mutated, param in self.mutate_request(request, 's74l7a', mode = 'replace'):
            occurences = await self.detect_context(mutated)
            positions = occurences.keys()
            
            if not occurences:
                continue
           
            #log_debug(f'Reflections found in {param} for {mutated.url}: {len(occurences)}')
            
            efficiencies = await self.filter_checker(request, param, occurences)
            
            tasks = [
                asyncio.create_task(
                    self.test_xss(mutated, param, payload, efficiencies, positions)
                )
                for payload in self.iter_payloads(self.wordlist_path)
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
                
    async def test_xss(self, request: Request, param, payload, occurences, positions):

        efficiencies, mutated, mutated_response = await self.checker(request, param, payload, positions)
        #log_debug(f'testing {mutated}')

        payload_context = self.classify_xss_payload(payload)
        
        if not efficiencies:
            for i in range(len(occurences)):
                efficiencies.append(0)
        
        matched_effs = []
        for pos, eff in zip(positions, efficiencies):
            if occurences[pos]['context'] == payload_context:
                matched_effs.append(eff)

        if not matched_effs:
            return False

        bestEfficiency = max(matched_effs)

        csp_blocks = csp_blocks_inline(mutated_response.headers)
        if bestEfficiency == 100 and not csp_blocks:
            url = mutated.url.replace('st4r7s', '')
            url = url.replace('3nd', '')
            
            log_vulnerability('CRITICAL', f'Reflected XSS Vulnerability Found')
            log_detail(f'Target', f'{url} {mutated.method}')
            log_detail(f'Parameter', param)
            log_detail(f'Payload', payload)
            log_detail(f'Context', payload_context)
            log_detail(f'Efficiency', bestEfficiency)
            log_detail('')
            
            report.report_vulnerability(
                'CRITICAL',
                'XSS',
                'XSS Reflected Vulnerability',
                {
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': payload,
                    'Context': payload_context,
                    'Efficiency': bestEfficiency
                }
            )
            return True
        
        elif bestEfficiency >= 99 and not csp_blocks:
            url = mutated.url.replace('st4r7s', '')
            url = url.replace('3nd', '')
            
            log_vulnerability('MEDIUM', f'Potential XSS Vulnerability Found')
            log_detail(f'Target', f'{url}')
            log_detail(f'Method', mutated.method)
            log_detail(f'Parameter', param)
            log_detail(f'Payload', payload)
            log_detail(f'Efficiency', bestEfficiency)
            log_detail('')
            
            report.report_vulnerability(
                'MEDIUM',
                'XSS',
                'Potential XSS Vulnerability',
                {
                    'Target': mutated.url,
                    'Method': mutated.method,
                    'Parameter': param,
                    'Payload': payload,
                    'Efficiency': bestEfficiency
                }
            )
            return True

        elif csp_blocks:
            log_vulnerability('LOW', f'Potential XSS blocked by CSP')
            log_detail(f'Target', mutated.url)
            log_detail(f'Method', mutated.method)
            log_detail(f'Parameter', param)
            log_detail(f'Payload', payload)
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
                    'Payload': payload,
                    'Efficiency': bestEfficiency
                }
            )
            return True

    async def detect_context(self, mutated: Request):

        try:
            response = await self.crawler.send(mutated, timeout = 1.5)
        except Exception as e:
            return {}

        text = response.text
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
                
        def escaped(position, string):
            usable = string[:position][::-1]
            match = re.search(r'^\\*', usable)
            if match:
                match = match.group()
                if len(match) == 1:
                    return True
                elif len(match) % 2 == 0:
                    return False
                else:
                    return True
            else:
                return False

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
        
    def classify_xss_payload(self, payload: str) -> str:
        p = payload.strip()

        if '-->' in p or p.startswith('-->') or p.endswith('<!--'):
            return 'comment'

        if re.match(r'^<\s*\w+', p):
            return 'html'

        if '=' in p and re.search(r'on\w+\s*=', p):
            return 'attribute'
        if (p.startswith('"') or p.startswith("'")) and p.count(p[0]) >= 2:
            return 'attribute'

        if any(tok in p for tok in (';', '()', ')', '//', 'alert', 'console')) or '`' in p:
            return 'script'

        return 'html'

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
        filled_positions = self.fill_holes(positions, reflected_positions)

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


    def fill_holes(self, original, new):
        filler = 0
        filled = []

        for x, y in zip(original, new):
            if int(x) == y + filler:
                filled.append(y)
            else:
                filled.extend([0, y])
                filler += (int(x) - y)

        return filled


    def check_dom(self, text):
        RED = '\033[91m'
        YELLOW = '\033[93m'
        END = '\033[0m'
        highlighted = []

        sources_pattern = (
            r'''\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)'''
            r'''|location\.(href|search|hash|pathname)|window\.name'''
            r'''|history\.(pushState|replaceState)(local|session)Storage)\b'''
        )
        sinks_pattern = (
            r'''\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen'''
            r'''|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript'''
            r'''|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent'''
            r'''|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML'''
            r'''|Range\.createContextualFragment|(document|window)\.location)\b'''
        )

        scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', text)
        sink_found = False
        source_found = False

        for script in scripts:
            lines = script.split('\n')
            all_controlled_vars = set()

            try:
                for original_line in lines:
                    parts = original_line.split('var ')
                    controlled_vars = set()
                    line = original_line

                    if len(parts) > 1:
                        for part in parts:
                            for var in all_controlled_vars:
                                if var in part:
                                    match = re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part)
                                    if match:
                                        controlled_vars.add(match.group().replace('$', r'\$'))

                    for grp in re.finditer(sources_pattern, original_line):
                        source = original_line[grp.start(): grp.end()].replace(' ', '')
                        if source:
                            if len(parts) > 1:
                                for part in parts:
                                    if source in part:
                                        match = re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part)
                                        if match:
                                            controlled_vars.add(match.group().replace('$', r'\$'))
                            line = line.replace(source, f"{YELLOW}{source}{END}")

                    all_controlled_vars.update(controlled_vars)

                    for var in all_controlled_vars:
                        if re.search(rf'\b{var}\b', line):
                            source_found = True
                            line = re.sub(rf'\b{var}\b', f"{YELLOW}{var}{END}", line)

                    for grp in re.finditer(sinks_pattern, original_line):
                        sink = original_line[grp.start(): grp.end()].replace(' ', '')
                        if sink:
                            line = line.replace(sink, f"{RED}{sink}{END}")
                            sink_found = True

                    if line != original_line:
                        highlighted.append(f"{line.lstrip(' ')}")

            except MemoryError:
                continue

        if sink_found or source_found:
            return highlighted
        return []

def csp_blocks_inline(headers):
        csp = ''
        for k, v in headers.items():
            if k.lower() == 'content-security-policy':
                csp = v
                break

        # If no CSP header, assume not blocking
        if not csp:
            return False

        # If unsafe-inline is present in script-src, inline scripts are allowed
        script_src_match = re.search(r"script-src\s+([^;]*)", csp)
        if script_src_match:
            script_src = script_src_match.group(1)
            # Allow inline scripts if unsafe-inline or strict-dynamic
            if "'unsafe-inline'" in script_src or "'strict-dynamic'" in script_src:
                return False

        # Otherwise, block
        return True