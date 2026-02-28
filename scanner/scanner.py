import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "UniWebScanner/2.1"}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>"
]

SQLI_PAYLOADS = [
    "'",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1"
]

TIME_PAYLOADS = [
    "' OR SLEEP(5)--"
]

SQL_ERRORS = [
    "sql syntax", "mysql", "syntax error",
    "unclosed quotation", "sqlite", "ora-", "odbc"
]

IGNORE_FIELDS = [
    "submit", "login", "btn", "token", "csrf", "max_file_size"
]

visited = set()

# ---------------- CRAWLER ----------------
def crawl(session, url, depth, max_depth, domain, pages):
    if depth > max_depth or url in visited:
        return
    if "logout" in url or "setup" in url:
        return

    visited.add(url)

    try:
        r = session.get(url, headers=HEADERS, timeout=10)
    except:
        return

    if not r or not r.text:
        return

    pages.append((url, r.text))
    soup = BeautifulSoup(r.text, "html.parser")

    for a in soup.find_all("a", href=True):
        link = urljoin(url, a["href"])
        if urlparse(link).netloc == domain:
            crawl(session, link, depth + 1, max_depth, domain, pages)

# ---------------- FORMS ----------------
def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for f in soup.find_all("form"):
        action = urljoin(base_url, f.get("action", ""))
        method = f.get("method", "get").lower()
        inputs = {}

        for i in f.find_all("input"):
            name = i.get("name")
            value = i.get("value", "")
            if name:
                inputs[name] = value

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return forms

# ---------------- FORM TESTING ----------------
def scan_form(session, form, run_xss, run_sqli):
    results = []

    for field in form["inputs"]:
        if any(x in field.lower() for x in IGNORE_FIELDS):
            continue

        base_data = form["inputs"].copy()

        # ---------- XSS ----------
        if run_xss:
            for payload in XSS_PAYLOADS:
                data = base_data.copy()
                data[field] += payload

                r = session.post(form["action"], data=data) \
                    if form["method"] == "post" \
                    else session.get(form["action"], params=data)

                if payload in r.text:
                    index = r.text.find(payload)
                    snippet = r.text[max(0, index-40): index+len(payload)+40]

                    results.append({
                        "type": "XSS",
                        "url": r.url,
                        "param": field,
                        "method": form["method"].upper(),
                        "payload": payload,
                        "evidence": snippet
                    })

        # ---------- SQL ERROR ----------
        if run_sqli:
            for payload in SQLI_PAYLOADS:
                data = base_data.copy()
                data[field] += payload

                r = session.post(form["action"], data=data) \
                    if form["method"] == "post" \
                    else session.get(form["action"], params=data)

                for err in SQL_ERRORS:

                    if err in r.text.lower():
                        index = r.text.lower().find(err)
                        snippet = r.text[max(0, index-40): index+40]

                        results.append({
                            "type": "SQLi (Error)",
                            "url": r.url,
                            "param": field,
                            "method": form["method"].upper(),
                            "payload": payload,
                            "evidence": snippet
                        })
                        break

        # ---------- SQL TIME ----------
        if run_sqli:
            for payload in TIME_PAYLOADS:
                data = base_data.copy()
                data[field] += payload

                start = time.time()
                session.post(form["action"], data=data) \
                    if form["method"] == "post" \
                    else session.get(form["action"], params=data)

                delay = time.time() - start
                if delay >= 5:
                    results.append({
                        "type": "SQLi (Time)",
                        "url": form["action"],
                        "param": field,
                        "method": form["method"].upper(),
                        "payload": payload,
                        "evidence": f"Response delayed by {delay:.2f} seconds"
                    })

    return results

# ---------------- COOKIE PARSER ----------------
def parse_cookie(cookie_str):
    cookies = {}
    if cookie_str:
        for item in cookie_str.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                cookies[k] = v
    return cookies

# ---------------- MAIN SCAN ----------------
def scan(target, run_xss=True, run_sqli=True, cookie=None):
    session = requests.Session()

    if cookie:
        session.cookies.update(cookie)
        print("[+] Authenticated scan using cookie")
    else:
        print("[!] No cookie provided → public scan only")

    visited.clear()
    pages = []

    crawl(session, target, 0, 2, urlparse(target).netloc, pages)

    findings = []
    for url, html in pages:
        forms = extract_forms(html, url)
        for f in forms:
            findings.extend(scan_form(session, f, run_xss, run_sqli))

    # Remove duplicates
    unique = []
    seen = set()
    for f in findings:
        key = (f["type"], f["url"], f["param"], f["payload"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique

# ---------------- DJANGO ENTRY ----------------
def scan_target(url, run_xss=True, run_sqli=True, cookie_header=None):
    cookie = parse_cookie(cookie_header) if cookie_header else None

    results = scan(
        target=url,
        run_xss=run_xss,
        run_sqli=run_sqli,
        cookie=cookie
    )

    formatted = []
    for r in results:
        formatted.append({
            "vuln_type": r.get("type"),
            "url": r.get("url"),
            "method": r.get("method"),
            "parameter": r.get("param"),
            "payload": r.get("payload"),
            "evidence": r.get("evidence")
        })

    return formatted
