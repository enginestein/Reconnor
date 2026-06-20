import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
]

XFH_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Host",
    "X-Rewrite-URL",
    "X-Original-URL",
    "Forwarded",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-Host",
    "X-Backend-Host",
]

ORIGIN_HEADERS = [
    "Origin",
    "Referer",
]


class HostHeaderInjection:
    name = "host-header-injection"
    description = "Host header injection scanner (cache poisoning, password reset poisoning, SSRF)"

    @staticmethod
    def run(target, timeout=10, ollama_model=None):
        section(f"Host Header Injection Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "vulnerabilities": [], "total_tests": 0, "findings": 0}
        all_vulns = []

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        original_host = parsed.netloc or parsed.hostname

        all_payloads = list(HOST_HEADER_PAYLOADS)
        if ollama and ollama.available:
            ai_payloads = ollama.generate_host_header_payloads(original_host)
            if ai_payloads:
                seen = set(all_payloads)
                for p in ai_payloads:
                    if p not in seen:
                        all_payloads.append(p)
                        seen.add(p)
                info(f"AI contributed {len(ai_payloads)} payloads")

        info("Testing Host header injection...")

        # Test 1: Basic Host header tampering
        for payload in all_payloads:
            results["total_tests"] += 1
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={
                        "Host": payload,
                        "User-Agent": "Mozilla/5.0",
                    },
                    allow_redirects=False)

                body_lower = resp.text.lower()
                host_list = [original_host.lower(), payload.lower()]
                lines_with_host = [l for l in body_lower.split("\n") if any(h in l for h in host_list)]

                if len(body_lower) > 100:
                    if payload.lower() in body_lower:
                        all_vulns.append({
                            "type": "HOST_HEADER", "payload": f"Host: {payload}",
                            "evidence": f"Payload reflected in response body",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[HOST_HEADER] Host: {payload} reflected in response ({resp.status_code})")

                    if resp.status_code in (200, 302, 301) and len(body_lower) > 500 and payload.lower() in body_lower:
                        all_vulns.append({
                            "type": "HOST_HEADER_CONTENT",
                            "payload": f"Host: {payload}",
                            "evidence": f"Host value incorporated into response content",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        warning(f"[HOST_HEADER_CONTENT] Host: {payload} influences content ({resp.status_code})")

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        # Test 2: X-Forwarded-Host and similar headers
        for xfh in XFH_HEADERS:
            for payload in all_payloads[:3]:
                results["total_tests"] += 1
                try:
                    resp = requests.get(target, timeout=timeout,
                        headers={
                            xfh: payload,
                            "User-Agent": "Mozilla/5.0",
                        },
                        allow_redirects=False)

                    if payload.lower() in resp.text.lower():
                        all_vulns.append({
                            "type": f"XFH_{xfh.upper().replace('-', '_')}",
                            "payload": f"{xfh}: {payload}",
                            "evidence": f"Payload reflected in response body",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[{xfh}] {xfh}: {payload} reflected in response ({resp.status_code})")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        # Test 3: Password reset poisoning test (check Location header in redirects)
        if ollama and ollama.available:
            info("Testing password reset poisoning vectors...")
        for payload in all_payloads[:3]:
            for xfh in XFH_HEADERS[:3]:
                results["total_tests"] += 1
                try:
                    resp = requests.get(target + "/reset-password", timeout=timeout,
                        headers={
                            xfh: payload,
                            "User-Agent": "Mozilla/5.0",
                        },
                        allow_redirects=False)

                    loc = resp.headers.get("Location", "")
                    if payload.lower() in loc.lower():
                        all_vulns.append({
                            "type": "PASSWORD_RESET_POISON",
                            "payload": f"{xfh}: {payload}",
                            "evidence": f"Location header: {loc}",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[PASSWORD_RESET_POISON] {xfh}: {payload} in Location header")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        # Test 4: Cache poisoning via Host
        info("Testing cache poisoning vectors...")
        for payload in all_payloads[:3]:
            results["total_tests"] += 1
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={
                        "Host": payload,
                        "User-Agent": "Mozilla/5.0",
                    },
                    allow_redirects=False)

                cache_headers = ["X-Cache", "X-Cache-Hit", "Age", "CF-Cache-Status", "X-Varnish", "X-Served-By", "X-Cache-Lookup"]
                cacheable = any(
                    h.lower() in dict(resp.headers).keys() or
                    (resp.headers.get(h) and resp.headers.get(h) != "miss")
                    for h in cache_headers
                )

                if cacheable and payload.lower() in resp.text.lower():
                    all_vulns.append({
                        "type": "CACHE_POISONING",
                        "payload": f"Host: {payload}",
                        "evidence": "Cache headers present + payload in response",
                        "status_code": resp.status_code,
                    })
                    results["findings"] += 1
                    warning(f"[CACHE_POISONING] Host: {payload} - cached content reflects injected host")

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))

            table(["Type", "Payload", "Evidence", "Status"], [
                [v["type"], v["payload"][:50], v["evidence"][:40], str(v["status_code"])] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No host header injection vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        return results
