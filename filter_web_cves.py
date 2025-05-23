import requests
import gzip
import json
import os

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
YEARS = list(range(2013, 2025))

KEYWORDS = [
    "xss", "cross-site scripting", "sql injection", "command injection", "code injection", "csrf",
    "cross-site request forgery", "open redirect", "path traversal", "directory traversal",
    "local file inclusion", "remote file inclusion", "rfi", "lfi", "file upload", "file download",
    "unauthenticated", "authentication bypass", "authorization bypass", "session fixation",
    "session hijacking", "cookie theft", "cookie injection", "http response splitting", "clickjacking",
    "frame injection", "javascript injection", "html injection", "php injection", "template injection",
    "ssti", "server-side template injection", "deserialization", "insecure deserialization", "web shell",
    "arbitrary file upload", "arbitrary file write", "arbitrary code execution", "remote code execution",
    "rce", "insecure direct object reference", "idor", "sensitive data exposure", "information disclosure",
    "directory listing", "misconfiguration", "admin panel", "debug mode", "exposed dashboard",
    "publicly accessible", "url manipulation", "parameter tampering", "header injection",
    "host header injection", "xml injection", "xxe", "xml external entity", "cors misconfiguration",
    "csp bypass", "content security policy", "captcha bypass", "2fa bypass", "jwt manipulation",
    "token spoofing", "access control", "broken access control", "bypass authentication",
    "bypass login", "exposed endpoint", "websocket injection", "log injection", "log poisoning",
    "log forging", "crlf injection", "web admin", "web portal", "web interface"
]

def download_feed(year):
    url = NVD_FEED_URL.format(year=year)
    filename = f"nvdcve-1.1-{year}.json.gz"
    if not os.path.exists(filename):
        print(f"Downloading: {url}")
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        else:
            raise Exception(f"Failed to download {url}")
    return filename

def load_cve_data(file_path):
    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('CVE_Items', [])

def is_web_vulnerability(description):
    return any(kw in description.lower() for kw in KEYWORDS)

def extract_cve_info(item):
    cve_id = item['cve']['CVE_data_meta']['ID']
    description = item['cve']['description']['description_data'][0]['value']
    published_date = item.get('publishedDate', '')
    last_modified_date = item.get('lastModifiedDate', '')
    references = [ref['url'] for ref in item['cve'].get('references', {}).get('reference_data', [])]

    # CVSS scores
    cvss_v3 = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
    cvss_v2 = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})

    score = cvss_v3.get('baseScore') or cvss_v2.get('baseScore')
    severity = cvss_v3.get('baseSeverity') or item.get('impact', {}).get('baseMetricV2', {}).get('severity')

    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": published_date,
        "last_modified_date": last_modified_date,
        "cvss_score": score,
        "severity": severity,
        "references": references
    }

def filter_web_cves(cve_items):
    filtered = []
    for item in cve_items:
        try:
            description = item['cve']['description']['description_data'][0]['value']
            if is_web_vulnerability(description):
                filtered.append(extract_cve_info(item))
        except (KeyError, IndexError):
            continue
    return filtered

def main():
    all_filtered = []
    for year in YEARS:
        gz_path = download_feed(year)
        print(f"Processing {gz_path}...")
        cve_items = load_cve_data(gz_path)
        filtered = filter_web_cves(cve_items)
        all_filtered.extend(filtered)

    with open("web_cves_all.json", 'w', encoding='utf-8') as f:
        json.dump(all_filtered, f, indent=2)
    print(f"Saved {len(all_filtered)} total web-related CVEs to web_cves_all.json")

if __name__ == "__main__":
    main()
