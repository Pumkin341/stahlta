
import bs4 as BeautifulSoup
import re
from urllib.parse import urlparse, urlunparse, urljoin
from posixpath import normpath

from components.parsers.dynamic import js_redirections
from components.web.request import Request

AUTOFILL= {
    "checkbox": "default",
    "color": "#BF40BF",
    "date": "2024-10-10",
    "datetime": "2024-10-10T12:12:12.12",
    "datetime-local": "2024-10-10T12:12",
    "email": "test@gmail.com",
    "file": ("image.png", b"\x89PNG\r\n\x1a\n", "image/png"),
    "hidden": "default",
    "month": "2024-10",
    "number": "1337",
    "password": "St@hlta20_", 
    "radio": "on",
    "range": "37",
    "search": "default",
    "submit": "submit",
    "tel": "0123456789",
    "text": "default",
    "time": "13:37",
    "url": "https://www.example.com",
    "username": "andrei",
    "week": "2024-W10"
}

DISCONNECT_REGEX = r'(?i)(?<![A-Za-z0-9])(?:log(?:[-_\s]?out)?|out|sign(?:[-_\s]?(?:off|out))|disconnect)(?![A-Za-z0-9])'


CONNECT_ERROR_REGEX = [r'(invalid|', r'authentication failed|', r'denied|', r'incorrect|',r'failed|', r'not found|',\
    r'expired|', r'try again|', r'captcha|', r'two-factors|', r'verify your email)']


def get_input_field_value(input_field) -> str:
    """Returns the value that we should fill the field with"""
    input_type = input_field.attrs.get("type", "text").lower()
    input_name = input_field["name"].lower()
    fallback = input_field.get("value", "")

    if fallback:
        return fallback

    if input_type == "text":
        if "mail" in input_name:
            return AUTOFILL["email"]
        if "pass" in input_name or "pwd" in input_name:
            return AUTOFILL["password"]
        if "user" in input_name or "login" in input_name:
            return AUTOFILL["username"]

    return AUTOFILL[input_type]

class HTML:
    def __init__(self, content : str, url : str, allow_fragments : bool = True):
        
        self._content = content
        self._url = url
        self._allow_fragments = allow_fragments
        self._encoding = 'utf-8'
        
        self._soup = BeautifulSoup.BeautifulSoup(content, 'html.parser')
        
        self._base = None
        base_tag = self._soup.find("base", href=True)
        if base_tag:
            base_parts = urlparse(base_tag["href"])
            current = urlparse(self._url)
            base_path = base_parts.path or "/"
            base_path = normpath(base_path.replace("\\", "/"))
            base_path = re.sub(r"^/{2,}", "/", base_path)
            if not base_path.endswith('/'):
                base_path += '/'

            self._base = urlunparse(
                (
                    base_parts.scheme or current.scheme,
                    base_parts.netloc or current.netloc,
                    base_path, "", "", ""
                )
            )
        
    def _urljoin(self, rel_url: str) -> str:
        return urljoin(self._base or self._url, rel_url, allow_fragments=self._allow_fragments)
    
    def _remove_fragment(self, url):
        if self._allow_fragments:
            return url
        else:
            return url.split('#')[0]
        
    def _script_urls_iterator(self):
        for script in self._soup.find_all("script", src=True):
            yield script["src"]
            
    def _links_raw_iterator(self):
        
        for nos in self._soup.find_all("noscript"):
            inner = nos.string or nos.decode_contents()
            inner_soup = BeautifulSoup.BeautifulSoup(inner, 'html.parser')
            for a in inner_soup.find_all("a", href=True):
                yield self._remove_fragment(a["href"]).strip()

        for tag in self._soup.find_all("a", href=True):
            yield self._remove_fragment(tag["href"]).strip()
            
        for tag in self._soup.find_all("area", href=True):
            yield self._remove_fragment(tag["href"]).strip()
            
        for tag in self._soup.find_all(["frame", "iframe"], src=True):
            yield self._remove_fragment(tag["src"]).strip()
            
        for tag in self._soup.find_all("form", action=True):
            yield tag["action"].strip()
            
        for tag in self._soup.find_all(["input", "button"], attrs={"formaction": True}):
            yield self._remove_fragment(tag["formaction"]).strip()
            
        for tag in self._soup.find_all("link", href=True):
            yield self._remove_fragment(tag["href"]).strip()
    
    def _links_iterator(self):
        for link in self._links_raw_iterator():
            yield self._urljoin(link)
        
    def forms_iterator(self):
        for form in self._soup.find_all("form"):
             
            url = self._urljoin(form.get("action", "").strip() or self._url)
            method = 'POST' if form.attrs.get("method", "GET").strip().upper() == "POST" else "GET"
            
            enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").strip()
             
            get_params = []
            post_params = []
            file_params = []    
            
            form_actions = set()
            radio = {}
            
            for input_field in form.find_all("input", attrs = {"name" : True}):
                input_type = input_field.attrs.get("type", "text").strip().lower() 
                
                if input_type in AUTOFILL:
                    if input_type == 'file':
                        if method == 'GET':
                            get_params.append([input_field["name"], "img.png"])
                            
                        else:
                            if 'multiple' in enctype:
                                file_params.append([input_field["name"], AUTOFILL['file']])
                                
                            else:
                                post_params.append([input_field["name"], 'img.png'])
                                
                    else:
                        value = get_input_field_value(input_field)
                        if input_type == 'radio':
                            radio[input_field["name"]] = value
                        elif method == 'GET':
                            get_params.append([input_field["name"], value])
                        else:
                            post_params.append([input_field["name"], value])
                            
                elif input_type == 'image':
                    if method == 'GET':
                        get_params.append([input_field["name"] + ".x", "1"])
                        get_params.append([input_field["name"] + ".y", "1"])
                    else:
                        post_params.append([input_field["name"] + ".x", "1"])
                        post_params.append([input_field["name"] + ".y", "1"])
                
            for input_field in form.find_all("input", attrs={"formaction": True}):
                form_actions.add(self._urljoin(input_field["formaction"].strip() or self._url))
            
            for button_field in form.find_all("button"):
                if "name" in button_field.attrs:
                    input_name = button_field["name"]
                    input_value = button_field.get("value", "")
                    if method == "GET":
                        get_params.append([input_name, input_value])
                    else:
                        post_params.append([input_name, input_value])

                if "formaction" in button_field.attrs:
                    form_actions.add(self._urljoin(button_field["formaction"].strip() or self._url))
                    
            if form.find("input", attrs={"name": False, "type": "image"}):
                if method == "GET":
                    get_params.append(["x", "1"])
                    get_params.append(["y", "1"])
                else:
                    post_params.append(["x", "1"])
                    post_params.append(["y", "1"])
                    
            for select in form.find_all("select", attrs={"name": True}):
                all_values = []
                selected_value = None
                for option in select.find_all("option", value=True):
                    all_values.append(option["value"])
                    if "selected" in option.attrs:
                        selected_value = option["value"]

                if selected_value is None and all_values:
                    selected_value = all_values[-1]

                if method == "GET":
                    get_params.append([select["name"], selected_value])
                else:
                    post_params.append([select["name"], selected_value])
                    
            for text_area in form.find_all("textarea", attrs={"name": True}):
                if method == "GET":
                    get_params.append([text_area["name"], "Hi there!"])
                else:
                    post_params.append([text_area["name"], "Hi there!"])
                    
            for radio_name, radio_value in radio.items():
                if method == "GET":
                    get_params.append([radio_name, radio_value])
                else:
                    post_params.append([radio_name, radio_value])

            if method == "POST" and not post_params and not file_params:
                continue

            new_form = Request(
                url,
                method=method,
                get_params=get_params,
                post_params=post_params,
                file_params=file_params,
                encoding=self._encoding,
                referer=self._url,
                enctype=enctype
            )
            yield new_form

            for url in form_actions:
                new_form = Request(
                    url,
                    method=method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype
                )
                yield new_form
                
    def find_login_form(self):
        for form in self.soup.find_all("form"):
            username_keys = []
            password_keys = []

            for input_field in form.find_all("input", attrs={"name": True}):
                input_type = input_field.attrs.get("type", "text").lower()
                name = input_field.attrs["name"]
                name_l = name.lower()
                id_l   = input_field.attrs.get("id", "").lower()

                is_user = (
                    input_type == "email"
                    or (input_type == "text" and any(tok in name_l for tok in ["mail", "user", "login", "name", "email", "username"]))
                    or (input_type == "text" and any(tok in id_l for tok in ["mail", "user", "login", "name", "email", "username"]))
                    or (input_type == "username" and any(tok in name_l for tok in ["mail", "user", "login", "name", "email", "username"]))
                )
                if is_user:
                    username_keys.append(name)

                if input_type == "password":
                    password_keys.append(name)
                    
            if len(username_keys) == 1 and len(password_keys) == 1:
                inputs = form.find_all("input", attrs={"name": True})
                url     = self._urljoin(form.attrs.get("action", "").strip() or self._url)
                method  = form.attrs.get("method", "GET").strip().upper()
                enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()

                if method == "POST":
                    post_params = {
                        inp["name"]: inp.get("value", "")
                        for inp in inputs
                    }
                    get_params = {}
                else:
                    get_params = {
                        inp["name"]: inp.get("value", "")
                        for inp in inputs
                    }
                    post_params = {}

                login_form = Request(
                    url,
                    method=method,
                    post_params=post_params,
                    get_params=get_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype,
                )

                return login_form, username_keys[0], password_keys[0]
            
            elif len(username_keys) == 1 and len(password_keys) == 0:
                inputs  = form.find_all("input", attrs={"name": True})
                url     = self._urljoin(form.attrs.get("action", "").strip() or self._url)
                method  = form.attrs.get("method", "GET").strip().upper()
                enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()

                if method == "POST":
                    post_params = { inp["name"]: inp.get("value","") for inp in inputs }
                    get_params  = {}
                else:
                    get_params  = { inp["name"]: inp.get("value","") for inp in inputs }
                    post_params = {}

                login_form = Request(
                    url,
                    method=method,
                    post_params=post_params,
                    get_params=get_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype,
                )
                return login_form, username_keys[0], None
                

        all_inputs = self._soup.find_all("input", attrs={"name": True})
        ui = next(
            (i for i, inp in enumerate(all_inputs)
            if inp.attrs.get("type", "").lower() in ("email","text")
                or any(tok in inp.attrs.get("name","").lower() for tok in ("user","login","mail"))
                or any(tok in inp.attrs.get("id","").lower() for tok in ("user","login","mail"))),
            None
        )
        pi = next(
            (i for i, inp in enumerate(all_inputs)
            if inp.attrs.get("type", "").lower() == "password"),
            None
        )

        if ui is not None and pi is not None:
            username_key = all_inputs[ui]["name"]
            password_key = all_inputs[pi]["name"]

            post_params = {
                inp["name"]: inp.get("value", "")
                for inp in all_inputs
            }

            login_req = Request(
                url=self._url,
                method="POST",
                get_params={},
                post_params=post_params,
                encoding=self._encoding,
                referer=self._url,
                enctype="application/x-www-form-urlencoded"
            )
            return login_req, username_key, password_key

        return None, None, None

    
    
    def disconnect_urls(self):
        disconnect_urls = []
        for link in self.links:
            if re.search(DISCONNECT_REGEX, link) is not None:
                disconnect_urls.append(link)
        return disconnect_urls

    def logged_in(self) -> bool:
        for regex in CONNECT_ERROR_REGEX:
            if self._soup.find(string=regex) is not None:
                return False
        return self._soup.find(string=re.compile(DISCONNECT_REGEX)) is not None

    
    
    '''Setters and Getters'''
    @property
    def soup(self):
        return self._soup
    
    @property
    def scripts(self):
        return [self._urljoin(script) for script in self._script_urls()]
    
    @property
    def links(self):
        return [link for link in self._links_iterator()]
        
    @property
    def base(self):
        return self._base
    
    @property
    def js_redirections(self):
        redirections = []
        for url in js_redirections(self._content):
            redirections.append(self._urljoin(url))
            
        if "" in redirections:
            redirections.remove("")
            
        return redirections
    
    @property
    def html_redirections(self):
        urls = set()
        for meta_tag in self.soup.find_all("meta", attrs={"content": True, "http-equiv": True}):
            if meta_tag and meta_tag["http-equiv"].lower() == "refresh":
                content_str = meta_tag["content"]
                content_str_length = len(meta_tag["content"])
                url_eq_idx = content_str.lower().find("url=")

                if url_eq_idx >= 0:
                    if content_str[url_eq_idx + 4] in ("\"", "'"):
                        url_eq_idx += 1
                        if content_str.endswith(("\"", "'")):
                            content_str_length -= 1
                    url = content_str[url_eq_idx + 4:content_str_length]
                    if url:
                        urls.add(self._urljoin(url))
        return [url for url in urls if url]
    
    @property
    def extra_urls(self):
        for tag in self.soup.find_all(["area", "base", "link"], href=True):
            yield self._urljoin(tag["href"])
            
        for tag in self.soup.find_all(["audio", "embed", "img", "script", "source", "track", "video"], src=True):
            yield self._urljoin(tag["src"])
            
        for tag in self.soup.find_all(["blockquote", "del", "ins", "q"], cite=True):
            yield self._urljoin(tag["cite"])
            
        for tag in self.soup.find_all("object", data=True):
            yield self._urljoin(tag["data"])
            
        for tag in self.soup.find_all("param", attrs={"name": "movie", "value": True}):
            yield self._urljoin(tag["value"])
            
        for tag in self.soup.find_all(["img", "source"], srcset=True):
            for source_desc in tag["srcset"].split(","):
                url = source_desc.strip().split(" ")[0]
                if url:
                    yield self._urljoin(url) 
    