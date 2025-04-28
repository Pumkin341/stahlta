import re
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl
from urllib.parse import urlparse

def js_redirections(text: str):
    """
    Scans the given JavaScript text and returns a list of unique URLs that are used for redirection.
    It extracts URLs from both location assignments and window.open calls.
    """
    JS_REDIRECT_REGEX = re.compile(r"\b(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*(\"|')([^\"']+)\1\s*(?:;|}|$)")
    WINDOW_OPEN_REGEX = re.compile(r"\bwindow\.open\(\s*(\"|')([^\"']+)\1\s*\)")
    
    urls_from_location = {match.group(2) for match in JS_REDIRECT_REGEX.finditer(text)}
    urls_from_window = {match.group(2) for match in WINDOW_OPEN_REGEX.finditer(text)}
    
    all_redirection_urls = urls_from_location.union(urls_from_window)
    return list(all_redirection_urls)

def dynamic_links(data: str, url: str):
    try:
        fld = get_fld(url)
    except (TldDomainNotFound, TldBadUrl):
        fld = urlparse(url).netloc

    path_found = []
    domain_found = []
    links = []

    base = urlparse(url)
    target_url = f"{base.scheme}://{base.netloc}"
    domain_found.append(target_url)
    domain_found.append(target_url)

    # extract literal “path”-style strings
    data_found = re.findall(r"(?:path|redirectTo|templateUrl)[\"']?:\s?[\"'](?P<path>[^\"'+*$(]*)[\"']", data)
    data_found += re.findall(r"\[\"(?:href|src)[\"'],\s?[\"'](?P<path>[^\"'(:]*)[\"']",data)
    data_found += re.findall(r"router\.(?:navigateByUrl|parseUrl|isActive)\([\w\s.+]*[\"'](?P<path>.*?)[\"'].*?\)", data)
    data_with_params = re.findall(r"router\.(?:navigate|createUrlTree)\(\[[\w\s]*[\"'](?P<path>.*?[\"'].*?)\](?:.*?)\)", data)
    
    # clean up array-of-params patterns
    for i, dp in enumerate(data_with_params):
        tmp = re.sub(r'["+\s]', '', dp)    # strip quotes, pluses, whitespace
        tmp = re.sub(r'/,', '/', tmp)      # fix leftover commas
        data_with_params[i] = tmp.replace(',', '/')
    data_found += data_with_params

    data_found += re.findall(r"this\.http\.(?:get|post|put|delete|patch)\(\s*this\.hostServer\s*\+\s*['\"](?P<path>[^'\"]+)['\"]", data)
    data_found += re.findall(r"this\.http\.(?:get|post|put|delete|patch)\(\s*`(?:\$\{this\.hostServer\})([^`]+)`", data)
    
    for path in data_found:
        if path and "http" not in path and path not in path_found:
            path_found.append(path)

    # catch any hard‑coded full URLs on our same domain
    raw_urls = re.findall(r"https?:\/\/[^\"'\\ )]+", data)
    for raw in raw_urls:
        u = raw.rstrip('<>"\') ')
        try:
            if fld == get_fld(u) and u not in domain_found:
                domain_found.append(u)
                links.append(u)
        except (TldDomainNotFound, TldBadUrl):
            continue

    # build final URLs by combining each domain with each path
    for u in domain_found:
        parts  = urlparse(u)
        scheme = parts.scheme
        domain = parts.netloc
        for path in path_found:
            p = path if path.startswith("/") else f"/{path}"
            new = f"{scheme}://{domain}{p}"
            if new not in links:
                links.append(new)

    return links
