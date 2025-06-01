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
        if not request.get_params and not request.post_params:
            return
        
        dom = self.check_dom(response.text)
        if dom:
            log_vulnerability('LOW', 'Potential DOM-based XSS found:')
            log_detail('Target', request.url)
            for line in dom:
                print(line)
            print()
        
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

        efficiencies, mutated = await self.checker(request, param, payload, positions)
        #log_debug(f'testing {mutated}')
        status_update(mutated.url)

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

        if bestEfficiency == 100:
            url = mutated.url.replace('st4r7s', '')
            url = url.replace('3nd', '')
            
            log_vulnerability('CRITICAL', f'Reflected XSS Vulnerability Found')
            log_detail(f'Target', f'{url} {mutated.method}')
            log_detail(f'Parameter', param)
            log_detail(f'Payload', payload)
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
                    'Efficiency': bestEfficiency
                }
            )
            return True
        
        elif bestEfficiency >= 99:
            url = mutated.url.replace('st4r7s', '')
            url = url.replace('3nd', '')
            
            log_vulnerability('MEDIUM', f'Potential XSS Vulnerability Found')
            log_detail(f'Target', f'{url} {mutated.method}')
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

    async def filter_checker(self, request, param, occurences):
        positions = occurences.keys()
        sortedEfficiencies = {}
        payloads = set(['<', '>'])
        for i in range(len(positions)):
            sortedEfficiencies[i] = {}
        for i in occurences:
            occurences[i]['score'] = {}
            context = occurences[i]['context']
            if context == 'comment':
                payloads.add('-->')
            elif context == 'script':
                payloads.add(occurences[i]['details']['quote'])
                payloads.add('</scRipT/>')
            elif context == 'attribute':
                if occurences[i]['details']['type'] == 'value':
                    if occurences[i]['details']['name'] == 'srcdoc': 
                        payloads.add('&lt;')  
                        payloads.add('&gt;')
                if occurences[i]['details']['quote']:
                    payloads.add(occurences[i]['details']['quote'])
                    
        for payload in payloads:
            if payload:
                efficiencies, _ = await self.checker(request, param, payload, positions)
                efficiencies.extend([0] * (len(occurences) - len(efficiencies)))
                for occurence, efficiency in zip(occurences, efficiencies):
                    occurences[occurence]['score'][payload] = efficiency
        return occurences

    async def checker(self, request: Request, param, payload, positions):
        checkString = 'st4r7s' + payload + '3nd'
        
        for mutated, param in self.mutate_request(request, checkString, mode= 'replace', parameter= param):
            async with self.semaphore:
                response = await self.crawler.send(mutated, timeout = 1.5)
        response = response.text
        
        reflectedPositions = []
        for match in re.finditer('st4r7s', response):
            reflectedPositions.append(match.start())
        filledPositions = self.fillHoles(positions, reflectedPositions)
        #  Itretating over the reflections
        num = 0
        efficiencies = []
        for position in filledPositions:
            allEfficiencies = []
            try:
                reflected = response[reflectedPositions[num]
                    :reflectedPositions[num]+len(checkString)]
                efficiency = fuzz.partial_ratio(reflected, checkString.lower())
                allEfficiencies.append(efficiency)
            except IndexError:
                pass
            if position:
                reflected = response[position:position+len(checkString)]
                efficiency = fuzz.partial_ratio(reflected, checkString)
                if reflected[:-2] == ('\\%s' % checkString.replace('st4r7s', '').replace('3nd', '')):
                    efficiency = 90
                allEfficiencies.append(efficiency)
                efficiencies.append(max(allEfficiencies))
            else:
                efficiencies.append(0)
            num += 1
        return list(filter(None, efficiencies)), mutated
    
    def fillHoles(self, original, new):
        filler = 0
        filled = []
        for x, y in zip(original, new):
            if int(x) == (y + filler):
                filled.append(y)
            else:
                filled.extend([0, y])
                filler += (int(x) - y)
        return filled
            
    def check_dom(self, response):
        red = '\033[91m'
        yellow = '\033[93m'
        end = '\033[0m'
        highlighted = []
        sources = r'''\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b'''
        sinks = r'''\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)\b'''
        scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)
        sinkFound, sourceFound = False, False
        for script in scripts:
            script = script.split('\n')
            allControlledVariables = set()
            try:
                for newLine in script:
                    line = newLine
                    parts = line.split('var ')
                    controlledVariables = set()
                    if len(parts) > 1:
                        for part in parts:
                            for controlledVariable in allControlledVariables:
                                if controlledVariable in part:
                                    controlledVariables.add(re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part).group().replace('$', '\\$'))
                    pattern = re.finditer(sources, newLine)
                    for grp in pattern:
                        if grp:
                            source = newLine[grp.start():grp.end()].replace(' ', '')
                            if source:
                                if len(parts) > 1:
                                    for part in parts:
                                        if source in part:
                                            controlledVariables.add(re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]+', part).group().replace('$', '\\$'))
                                line = line.replace(source, yellow + source + end)
                    for controlledVariable in controlledVariables:
                        allControlledVariables.add(controlledVariable)
                    for controlledVariable in allControlledVariables:
                        matches = list(filter(None, re.findall(r'\b%s\b' % controlledVariable, line)))
                        if matches:
                            sourceFound = True
                            line = re.sub(r'\b%s\b' % controlledVariable, yellow + controlledVariable + end, line)
                    pattern = re.finditer(sinks, newLine)
                    for grp in pattern:
                        if grp:
                            sink = newLine[grp.start():grp.end()].replace(' ', '')
                            if sink:
                                line = line.replace(sink, red + sink + end)
                                sinkFound = True
                    if line != newLine:
                        highlighted.append('%-3s %s' % ('-', line.lstrip(' ')))
            except MemoryError:
                pass
        if sinkFound or sourceFound:
            return highlighted
        else:
            return []
