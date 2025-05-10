
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

DISCONNECT_REGEX = r'(?i)((log|sign)\s?(out|off)|disconnect|déconnexion)'
CONNECT_ERROR_REGEX = r'(invalid|'\
                      r'authentication failed|'\
                      r'denied|'\
                      r'incorrect|'\
                      r'failed|'\
                      r'not found|'\
                      r'expired|'\
                      r'try again|'\
                      r'captcha|'\
                      r'two-factors|'\
                      r'verify your email|'\
                      r'erreur)'


def get_input_field_value(input_field) -> str:
    """Returns the value that we should fill the field with"""
    input_type = input_field.attrs.get("type", "text").lower()
    input_name = input_field["name"].lower()
    fallback = input_field.get("value", "")

    # If there is a non-empty default value, use it
    # If it is empty, it is OK if autofill is not set
    if fallback:
        return fallback

    # Otherwise use our hardcoded values
    if input_type == "text":
        if "mail" in input_name:
            return AUTOFILL["email"]
        if "pass" in input_name or "pwd" in input_name:
            return AUTOFILL["password"]
        if "user" in input_name or "login" in input_name:
            return AUTOFILL["username"]

    return AUTOFILL[input_type]

class HTML:
    def __init__(self, 
                 content : str,
                 url : str,
                 allow_fragments : bool = True):
        
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
            
            for input_field in form.find_all("input", attr = {"name" : True}):
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
                
            # A formaction doesn't need a name
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
                    # If formaction is empty it basically send to the current URL
                    # which can be different from the defined action attribute on the form...
                    form_actions.add(self._urljoin(button_field["formaction"].strip() or self._url))
                    
            if form.find("input", attrs={"name": False, "type": "image"}):
                # Unnamed input type file => names will be set as x and y
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
                    # First value may be a placeholder but last entry should be valid
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

            # First raise the form with the URL specified in the action attribute
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

            # Then if we saw some formaction attribute, raise the form with the given formaction URL
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
            username_field_idx = []
            password_field_idx = []

            for i, input_field in enumerate(form.find_all("input")):
                input_type = input_field.attrs.get("type", "text").lower()
                input_name = input_field.attrs.get("name", "undefined").lower()
                input_id = input_field.attrs.get("id", "undefined").lower()
                if input_type == "email":
                    username_field_idx.append(i)

                elif input_type == "text" and (
                        any(field_name in input_name for field_name in ["mail", "user", "login", "name", "email", "username"]) or
                        any(field_id in input_id for field_id in ["mail", "user", "login", "name", "email", "username"])
                ):
                    username_field_idx.append(i)

                elif input_type == "password":
                    password_field_idx.append(i)

            if len(username_field_idx) == 1 and len(password_field_idx) == 1:
                inputs = form.find_all("input", attrs={"name": True})

                url = self._urljoin(form.attrs.get("action", "").strip() or self._url)
                method = form.attrs.get("method", "GET").strip().upper()
                enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()
                post_params = []
                get_params = []
                if method == "POST":
                    post_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]
                else:
                    get_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]

                login_form = Request(
                    url,
                    method=method,
                    post_params=post_params,
                    get_params=get_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype,
                )

                return login_form, username_field_idx[0], password_field_idx[0]
            
        all_inputs = self._soup.find_all("input", attrs={"name": True})
        pw_idxs = [i for i, inp in enumerate(all_inputs)
                   if inp.attrs.get("type", "").lower() == "password"]
        user_idxs = [i for i, inp in enumerate(all_inputs)
                     if inp.attrs.get("type", "").lower() in ("email","text")
                        or any(tok in inp.attrs.get("name","").lower() for tok in ("user","login","mail"))
                        or any(tok in inp.attrs.get("id","").lower() for tok in ("user","login","mail"))]

        if pw_idxs and user_idxs:
            ui = user_idxs[0]
            pi = pw_idxs[0]

            post_params = []
            for inp in all_inputs:
                n = inp["name"]
                v = inp.get("value", "")
                post_params.append([n, v])

            login_req = Request(
                url=self._url,
                method="POST",
                get_params=[],
                post_params=post_params,
                encoding=self._encoding,
                referer=self._url,
                enctype="application/x-www-form-urlencoded"
            )
            return login_req, ui, pi

        return None, 0, 0

    
    
    def extract_disconnect_urls(self):
        """
        Extract all the disconnect urls on the given page and returns them.
        """
        disconnect_urls = []
        for link in self.links:
            if re.search(DISCONNECT_REGEX, link) is not None:
                disconnect_urls.append(link)
        return disconnect_urls

    def is_logged_in(self) -> bool:
        # If we find logging errors on the page
        if self._soup.find(string=re.compile(CONNECT_ERROR_REGEX)) is not None:
            return False
        # If we find a disconnect button on the page
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
    