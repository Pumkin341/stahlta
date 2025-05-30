from components.parsers.html import HTML
from components.web.request import Request
from components.web.crawler import Crawler
from components.main.logger import logger

from http.cookiejar import CookieJar, Cookie


async def log_in(crawler_config, username, password, login_url):
    
    disconnect_urls = []
    cookie_jar = None
    async with Crawler.client(crawler_config) as crawler:
        # try the login url
        try:
            response = await crawler.send(Request(login_url))
            text = response.text
        
        except Exception:
            logger.error(f"Connection error while trying to access {login_url}")
            return False, None, None, []
        
        else:
            
            if crawler_config.context:          
                cookie_jar = await build_cookiejar_from_context(crawler_config.context)
                crawler.cookie_jar = cookie_jar
            
            html = HTML(text, login_url)
            form, user_key, password_key = html.find_login_form()
            
            if not form or not user_key:
                logger.error("No login form (or username field) found on the login page")
                return False, None, None, []

            # 2 step auth
            if password_key is None:
                if form.method.upper() == "POST":
                    form.post_params[user_key] = username
                else:
                    form.get_params[user_key] = username

                req_step1 = Request(
                    form.url,
                    method=form.method,
                    get_params=form.get_params,
                    post_params=form.post_params,
                    depth=form.depth
                )
                
                # send only the post with username
                resp2 = await crawler.send(req_step1, redirect=True)

                html2 = HTML(resp2.text, str(resp2.url))
                form2, _, password_key = html2.find_login_form()
                
                if not form2 or password_key is None:
                    logger.error("Could not find password form after submitting username")
                    return False, None, None, []

                form = form2  # switch to the second‐step form

            # fill username + password
            if form.method.upper() == "POST":
                form.post_params[user_key] = username
                form.post_params[password_key] = password
            else:
                form.get_params[user_key] = username
                form.get_params[password_key] = password

            req_login = Request(
                form.url,
                method=form.method,
                get_params=form.get_params,
                post_params=form.post_params,
                depth=form.depth
            )
            
            # try the post form 
            response = await crawler.send(req_login, redirect= True)
            
            start_url = None
            if str(response.url) != req_login.url:
                start_url = Request(str(response.url))
                    
            login_html = HTML(response.text, req_login.url)
            state = login_html.logged_in()
            
            if state:
                logger.success('Login has been successful\n')
                
                cookie_jar = crawler.cookie_jar
                if crawler_config.context:
                    await apply_cookiejar_to_context(cookie_jar, crawler_config.context)
                
                disconnect_urls = login_html.disconnect_urls()
            
            else:
                logger.warning('Login has NOT been successful\n')
            
            return state, cookie_jar, start_url, disconnect_urls

async def build_cookiejar_from_context(context) -> CookieJar:
    jar = CookieJar()
    pw_cookies = await context.cookies()
    
    for c in pw_cookies:
        cookie = Cookie(
            version=0,
            name=c["name"],
            value=c["value"],
            port=None,
            port_specified=False,
            domain=c["domain"],
            domain_specified=bool(c["domain"]),
            domain_initial_dot=c["domain"].startswith("."),
            path=c["path"],
            path_specified=True,
            secure=c["secure"],
            expires=c.get("expires", None),
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": c.get("httpOnly", False),
                  "SameSite": c.get("sameSite")},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
        
    return jar

async def apply_cookiejar_to_context(jar: CookieJar, context) -> None:
  
    pw_cookies = []
    for c in jar:
        pw_cookies.append({
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "expires": int(c.expires) if c.expires is not None else -1,
            "httpOnly": bool(c._rest.get("HttpOnly", False)),
            "secure": bool(c.secure),
            "sameSite": str(c._rest.get("SameSite", "Lax")),
        })
        
    await context.add_cookies(pw_cookies)