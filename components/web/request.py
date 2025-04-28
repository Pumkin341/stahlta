from urllib.parse import urlparse, urlunparse, parse_qs


class Request():
    
    def __init__(self, url, method = '', get_params = {}, post_params = {}, file_params : list = [], depth :int = 0, encoding = 'utf-8', enctype = '', referer = ''):
        '''
        url      : "https://www.example.com:8080/path/to/page;params?arg1=value1&arg2=value2#section"
        scheme   : "https"        # The protocol used.
        netloc   : "www.example.com:8080"  # The domain and port.
        path     : "/path/to/page"  # The path to the resource.
        params   : "params"         # Parameters for the last path element (rarely used).
        query    : "arg1=value1&arg2=value2"  # Key-value pairs in the query string.
        fragment : "section"        # The anchor within the resource.
        hostname : "www.example.com"  # The domain name without the port.
        '''

        parts = urlparse(url)
        
        path = parts.path
        if path.endswith("index.html"):
            path = path[:-len("index.html")]
            if not path:
                path = "/"
        
        self._url = url
        self._resource_path = urlunparse((parts.scheme, parts.netloc, path, parts.params, '', ''))
        
        self._fragment = parts.fragment or ""
        self._file_path = parts.path
        self._netloc = parts.netloc
        self._scheme = parts.scheme
        self._hostname = parts.hostname
        
        self._depth = depth
        self._referer = referer
        self._headers = None
        self._response_content = None
        self._size = 0
        

        if not method:
            self._method = 'GET' if not post_params else 'POST'
        else:
            self._method = method.upper()
        
        self._enctype = ""
        if self._method in ["POST", "PUT", "PATCH"]:
            if enctype:
                self._enctype = enctype.lower().strip()
            else:
                if file_params:
                    self._enctype = "multipart/form-data"
                else:
                    self._enctype = "application/x-www-form-urlencoded"

        self._encoding = encoding
        
        '''
        ### List
        get_params = [
            ["username", "john_doe"],
            ["password", "securepassword123"]
        ]   
        
        ### URL Encoded
        get_params = "username=john_doe&password=securepassword123"
        
        post_params are the same as get_params.
        '''
            
        if isinstance(get_params, list):
            self._get_params = dict(get_params)
            
        elif isinstance(get_params, dict):
            self._get_params = get_params
            
        elif isinstance(get_params, str):
            tmp = {}
            for seg in get_params.split('&'):
                if '=' in seg:
                    k, v = seg.split('=', 1)
                else:
                    k, v = seg, ''
                tmp[k] = v
            self._get_params = tmp
            
        else:
            if parts.query:
                self._get_params = {k: v[0] for k, v in parse_qs(parts.query).items()}
            else:
                self._get_params = {}
        
        if not post_params:
            self._post_params = {}
            
        elif isinstance(post_params, dict):
            self._post_params = post_params
            
        elif isinstance(post_params, list):
            self._post_params = dict(post_params)
            
        elif isinstance(post_params, str):
            self._post_params = {}
            for param in post_params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    self._post_params[key] = value
                else:
                    self._post_params[param] = ''
        else:
            raise ValueError('Invalid post parameters (must be dict, list of pairs, or querystring).')  
        
        self._file_params = file_params
        if not file_params:
            self._file_params = []
        
    def __hash__(self):
        get_items  = tuple(sorted(self._get_params.items()))
        post_items = tuple(sorted(self._post_params.items()))
        file_items = tuple(sorted(tuple(fp) for fp in self._file_params))
        
        return hash((
            self._method,
            self._resource_path,
            get_items,
            post_items,
            file_items
        ))

    def __eq__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        
        our_files   = sorted(tuple(fp) for fp in self._file_params)
        their_files = sorted(tuple(fp) for fp in other.file_params)
        return (
            self._method == other.method and
            self._resource_path == other.path and
            self._get_params == other.get_params and
            self._post_params == other.post_params and
            our_files == their_files
        )
        
    def __repr__(self):
        return f"Request({self._url}, {self._method}, depth={self._depth}, get_params={self._get_params}, post_params={self._post_params})"
    
    '''
        Setters and Getters
    '''
    
    @property
    def url(self):
        return self._url
    
    @property
    def path(self):
        return self._resource_path
    
    @property
    def fragment(self):
        return self._fragment
    
    @property
    def file_path(self):
        return self._file_path
    
    @property
    def netloc(self):
        return self._netloc
    
    @property
    def scheme(self):
        return self._scheme
    
    @property
    def hostname(self):
        return self._hostname
    
    @property
    def depth(self):
        return self._depth
    
    @property
    def headers(self):
        return self._headers
    
    @property
    def response_content(self):
        return self._response_content
    
    @property
    def size(self):
        return self._size
    
    @property
    def method(self):
        return self._method
    
    @property
    def enctype(self):
        return self._enctype
    
    @property
    def encoding(self):
        return self._encoding
    
    @property
    def get_params(self):
        return self._get_params
    
    @property
    def file_params(self):
        return self._file_params
    
    @headers.setter
    def headers(self, headers):
        self._headers = headers
        
    @response_content.setter
    def response_content(self, content):
        self._response_content = content
        
    @depth.setter
    def depth(self, depth):
        self._depth = depth
        
    @size.setter
    def size(self, size):
        self._size = size
        
    @method.setter
    def method(self, method):
        self._method = method
        
    @enctype.setter
    def enctype(self, enctype):
        self._enctype = enctype
        
    @encoding.setter
    def encoding(self, encoding):
        self._encoding = encoding
        
    @get_params.setter
    def get_params(self, get_params):
        self._get_params = get_params
        
    @property
    def post_params(self):
        return self._post_params
    
    @post_params.setter
    def post_params(self, value):
        if not value:
            self._post_params = {}
        elif isinstance(value, dict):
            self._post_params = value
        elif isinstance(value, list):
            # list of [key, value] → convert to dict
            self._post_params = dict(value)
        elif isinstance(value, str):
            # query string like "a=1&b=2" → convert to dict
            self._post_params = {}
            for param in value.split('&'):
                if '=' in param:
                    key, val = param.split('=', 1)
                    self._post_params[key] = val
                else:
                    self._post_params[param] = ''
        else:
            raise ValueError('post_params must be dict, list of (key, value), or query string')
            
            