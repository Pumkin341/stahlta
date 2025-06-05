# from requests_html import AsyncHTMLSession
# import asyncio

# async def main(): 
#     asession = AsyncHTMLSession()
#     r = await asession.get('https://juice-shop.herokuapp.com/#/')
#     await r.html.arender()
#     soup = BeautifulSoup(r.html.html, 'html.parser')
#     print(soup.prettify())

# asyncio.run(main())   



# import asyncio
# from bs4 import BeautifulSoup
# from playwright.async_api import async_playwright
# import httpx
# from urllib.parse import urljoin

# from components.web.request import Request
# from components.web.crawler import CrawlerConfig, Crawler

# async def main1():
#     async with async_playwright() as p:
#         browser = await p.chromium.launch()
#         page = await browser.new_page()
        
#         response = await page.goto("http://juice-shop.com:3000/#/login")
#         text = await response.text()
#         soup_login = BeautifulSoup(text, 'html.parser')
        
#         print(soup_login.prettify())

#         await browser.close()
        
# async def main2():
#     async with httpx.AsyncClient() as client:
        
#         response_login = await client.get("http://juice-shop.com:3000/#/login")
#         soup_login = BeautifulSoup(response_login.text, 'html.parser')
#         print(soup_login.prettify())
        
#         await client.aclose()
    

# asyncio.run(main1())
# print("--" * 20)
# asyncio.run(main2())

#print(urljoin("http://juice-shop.com:3000/#/", '/login', allow_fragments=True))

# async def main():
#     request = Request("http://juice-shop.com:3000/login")

#     async with async_playwright() as p:
#         browser = await p.chromium.launch()
#         context = await browser.new_context()

#         # 1) give the crawler your BrowserContext
#         crawler = Crawler.client(CrawlerConfig(request, context=context))

#         # 2) manually verify via Playwright
#         page = await context.new_page()
#         await page.goto(request.url, wait_until='networkidle')
#         #print("Playwright DOM:\n", await page.content())

#         # 3) now crawler.get() will do the same
#         response = await crawler.get(request)
#         soup = BeautifulSoup(response.content, 'html.parser')
#         print("Crawler DOM:\n", soup.prettify())

# asyncio.run(main())
        

# dictt = {
#     "username": "admin",
#     "password": "admin"
# }
# print(dictt)
# print(dictt.items())

# for key, value in dictt:
#     print(key, value)

# client = httpx.Client(cookies= {'name': 'PHPSESSID', 'value': 'j6123fm7p5frllciu0jgpsvpme', 'domain': '192.168.224.1', 'path': '/', 'expires': 1747760583.100685, 'httpOnly': True, 'secure': False, 'sameSite': 'Strict'})
# response = client.get("http://192.168.224.1/DVWA/login.php")
# print(response.text)

import asyncio
from playwright.async_api import async_playwright

async def click_and_capture_xml(product_id: int, store_id: int):
    """
    - Goes to the product‐detail page for `product_id`
    - Chooses `store_id` from the <select>
    - Clicks “Check stock”
    - Waits for the POST to /catalog/product/stock
    - Returns the raw XML string that was sent
    """
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()

        # 1) Navigate to the product page (which loads xmlStockCheckPayload.js + stockCheck.js)
        url = f"https://ginandjuice.shop/catalog/product?productId={product_id}"
        await page.goto(url)

        # 2) Wait for the <select name="storeId"> to be ready, then choose our store
        await page.wait_for_selector("select[name=storeId]")
        await page.select_option("select[name=storeId]", str(store_id))

        async with page.expect_request("https://ginandjuice.shop/catalog/product/stock") as first:
            # 4) Click the “Check stock” button inside #stockCheckForm:
            await page.click("#stockCheckForm button[type=submit]")
            
        first_request = await first.value  
        return first_request
        

        
        
# Example usage:
if __name__ == "__main__":
    pid = 1
    sid = 3
    xml_request = asyncio.run(click_and_capture_xml(pid, sid))
    print("Captured XML payload:")
    print(xml_request.post_data)