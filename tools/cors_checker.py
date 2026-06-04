import re
import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table

CORS_ORIGIN_TESTS = [
    ("null", "null"),
    ("null_uppercase", "NULL"),
    ("null_mixed", "Null"),

    ("origin_mirror", "{scheme}://{domain}"),
    ("subdomain", "{scheme}://evil.{domain}"),
    ("different_domain", "https://evil.com"),
    ("different_domain_https", "https://attacker.com"),
    ("different_domain_http", "http://evil.com"),

    ("prefix", "{scheme}://evil{domain_origin}"),
    ("prefix_dash", "{scheme}://evil-{domain_origin}"),
    ("prefix_dot", "{scheme}://evil.{domain_origin}"),
    ("prefix_at", "{scheme}://evil@{domain_origin}"),
    ("prefix_at_www", "{scheme}://evil@www.{domain}"),

    ("suffix", "{scheme}://{domain_origin}.evil.com"),
    ("suffix_evil_tld", "{scheme}://{domain_origin}.evil"),
    ("suffix_attacker", "{scheme}://{domain_origin}.attacker.com"),

    ("subdomain_deep", "{scheme}://x.y.z.{domain}"),
    ("subdomain_wildcard", "{scheme}://www.{domain}.evil.com"),
    ("subdomain_wildcard_deep", "{scheme}://x.y.{domain}.evil.com"),

    ("tld_swap", "{scheme}://{domain_tld_swap}"),
    ("tld_missing", "{scheme}://{domain_sld}"),
    ("tld_different", "{scheme}://{domain_sld}.xyz"),

    ("scheme_switch", "http://{domain}"),
    ("scheme_https", "https://{domain}"),
    ("scheme_ftp", "ftp://{domain}"),
    ("scheme_file", "file://{domain}"),
    ("scheme_chrome", "chrome-extension://{domain}"),

    ("port_different", "{scheme}://{domain}:8080"),
    ("port_alt_http", "{scheme}://{domain}:81"),
    ("port_alt_https", "{scheme}://{domain}:8443"),
    ("port_9999", "{scheme}://{domain}:9999"),
    ("port_evil", "{scheme}://{domain}:31337"),

    ("trusted_tld", "{scheme}://{domain}.com"),
    ("trusted_net", "{scheme}://{domain}.net"),
    ("trusted_org", "{scheme}://{domain}.org"),

    ("encoded_null", "null%00"),
    ("encoded_dot", "{scheme}://evil%2e{domain}"),
    ("encoded_at", "{scheme}://evil%40{domain}"),
    ("double_dot", "{scheme}://evil..{domain}"),
    ("dots_in_host", "{scheme}://evil.com.{domain}"),

    ("ip_bypass", "{scheme}://127.0.0.1"),
    ("ip_bypass_local", "{scheme}://localhost"),
    ("ip_bypass_internal", "{scheme}://10.0.0.1"),
    ("ip_bypass_aws", "{scheme}://169.254.169.254"),

    ("refresh_header", "https://evil.com"),
    ("referer_header", "{scheme}://{domain}"),
    ("origin_referer_mismatch", "{scheme}://evil.com"),
    ("x_forwarded_host", "{scheme}://evil.com"),
]

CRITICAL_MISCONFIGS = [
    {"pattern": r"^\*$", "risk": "CRITICAL", "desc": "Wildcard ACAO"},
    {"pattern": r"^https?://null$", "risk": "CRITICAL", "desc": "Literal null origin"},
    {"pattern": r"^null$", "risk": "HIGH", "desc": "Null origin allowed"},
    {"pattern": r"^https?://evil\.", "risk": "HIGH", "desc": "Prefix-based reflection"},
    {"pattern": r"\.evil\.com$", "risk": "HIGH", "desc": "Suffix-based reflection"},
    {"pattern": r"^https?://[^/]+@", "risk": "HIGH", "desc": "Credentials in origin"},
    {"pattern": r"^http://", "risk": "MEDIUM", "desc": "HTTP origin allowed (MITM)"},
    {"pattern": r"^https?://[^/]+:[0-9]+", "risk": "MEDIUM", "desc": "Alternate port allowed"},
]

CORS_HEADERS_TO_CHECK = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Vary",
]

PREFLIGHT_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
PREFLIGHT_HEADERS = ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token", "X-API-Key", "Custom-Header"]


class AdvancedCORSChecker:
    name = "cors"
    description = "Advanced CORS misconfiguration scanner (preflight, credential leak, wildcard analysis, origin reflection)"

    @staticmethod
    def run(target, timeout=10):
        section(f"Advanced CORS Misconfiguration Scanner: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        domain = parsed.netloc
        scheme = parsed.scheme or "https"
        domain_parts = domain.split(".")
        sld = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
        tld_swapped = ".".join(domain_parts[:-1] + ["xyz"]) if len(domain_parts) >= 2 else domain

        origin_vars = {
            "{scheme}": scheme,
            "{domain}": domain,
            "{domain_origin}": sld,
            "{domain_sld}": sld,
            "{domain_tld_swap}": tld_swapped,
        }

        all_vulnerabilities = []
        preflight_results = []

        section("Phase 1: Direct Request Origin Reflection")
        info(f"Testing {len(CORS_ORIGIN_TESTS)} origin variations against main endpoint...")

        for test_name, origin_template in CORS_ORIGIN_TESTS:
            origin = origin_template
            for var, val in origin_vars.items():
                if var in origin:
                    origin = origin.replace(var, val)

            try:
                resp = requests.get(target, timeout=timeout,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                        "Origin": origin,
                        "Host": domain,
                        "Referer": f"{scheme}://{domain}/",
                    })

                acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip()
                vary = resp.headers.get("Vary", "").strip()
                am = resp.headers.get("Access-Control-Allow-Methods", "").strip()
                ah = resp.headers.get("Access-Control-Allow-Headers", "").strip()
                exh = resp.headers.get("Access-Control-Expose-Headers", "").strip()
                ma = resp.headers.get("Access-Control-Max-Age", "").strip()

                if acao:
                    matched_config = None
                    for cfg in CRITICAL_MISCONFIGS:
                        if re.search(cfg["pattern"], acao, re.I):
                            matched_config = cfg
                            break

                    if matched_config:
                        risk = matched_config["risk"]
                        desc = matched_config["desc"]
                        entry = {
                            "origin": origin, "test": test_name, "acao": acao,
                            "acac": acac, "vary": vary, "risk": risk, "desc": desc,
                            "methods": am, "headers": ah, "expose_headers": exh, "max_age": ma,
                        }

                        if acac.lower() == "true":
                            warning(f"[{risk}] [{test_name}] ACAO: {acao} + Credentials=true -> CREDENTIAL LEAK!")
                            entry["credential_leak"] = True
                        else:
                            warning(f"[{risk}] [{test_name}] ACAO: {acao} {desc}")

                        all_vulnerabilities.append(entry)

                        if risk == "CRITICAL":
                            AdvCCC = AdvancedCORSChecker
                            AdvCCC.test_preflight(target, scheme, domain, origin, acao, timeout, preflight_results)
                    else:
                        if acao == origin or acao == "*":
                            risk_level = "MEDIUM"
                            if acao == origin and acac.lower() == "true":
                                risk_level = "HIGH"
                                warning(f"[{risk_level}] [{test_name}] ACAO: {acao} (reflected) + Credentials -> possible db exfil")

                            all_vulnerabilities.append({
                                "origin": origin, "test": test_name, "acao": acao,
                                "acac": acac, "vary": vary, "risk": risk_level,
                                "desc": "Origin reflection" if acao == origin else "Wildcard",
                                "methods": am, "headers": ah, "expose_headers": exh, "max_age": ma,
                            })
                        elif resp.status_code not in (403, 404, 405):
                            info(f"[{test_name}] ACAO: {acao or 'not set'} (status {resp.status_code})")
            except Exception as e:
                info(f"[{test_name}] Error: {e}")

        section("Phase 2: Preflight (OPTIONS) Request Testing")
        if not preflight_results:
            AdvCCC = AdvancedCORSChecker
            AdvCCC.test_preflight(target, scheme, domain, f"{scheme}://evil.com", "", timeout, preflight_results)

        section("Phase 3: Credentialed Request Testing")
        cred_vulns = [v for v in all_vulnerabilities if "true" == v.get("acac", "").lower() and v["acao"] != "null"]
        if cred_vulns:
            warning(f"Found {len(cred_vulns)} misconfiguration(s) allowing credentialed requests")
            for v in cred_vulns:
                result(f"  [{v['risk']}]", f"{v['test']}: ACAO={v['acao']} | Cookies/auth tokens can be exfiltrated")

        section("Phase 4: Wildcard with Credentials Check")
        try:
            resp = requests.get(target, timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Origin": "*",
                })
            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip()
            if acao == "*" and acac.lower() == "true":
                warning("CRITICAL: Wildcard ACAO with credentials=true (browsers block this, but it indicates broken CORS logic)")
                all_vulnerabilities.append({
                    "origin": "*", "test": "wildcard_credentials",
                    "acao": "*", "acac": "true", "risk": "CRITICAL", "desc": "Wildcard + credentials",
                })
        except:
            pass

        section("Phase 5: Sensitive Endpoint CORS Testing")
        sensitive_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/admin", "/user", "/users", "/profile",
                          "/account", "/settings", "/config", "/secret", "/token", "/auth", "/login", "/oauth",
                          "/.env", "/debug", "/info"]
        for path in sensitive_paths:
            test_url = f"{scheme}://{domain}{path}"
            try:
                resp = requests.get(test_url, timeout=timeout,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                        "Origin": f"{scheme}://evil.com",
                    })
                acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip()
                if acao and resp.status_code not in (403, 404):
                    risk = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    warning(f"[{risk}] CORS on {path}: ACAO={acao} (HTTP {resp.status_code})")
                    all_vulnerabilities.append({
                        "origin": f"{scheme}://evil.com", "test": f"sensitive_path:{path}",
                        "acao": acao, "acac": acac, "risk": risk, "desc": f"CORS enabled on {path}",
                    })
            except:
                pass

        section("CORS Risk Assessment Summary")
        if all_vulnerabilities:
            critical = [v for v in all_vulnerabilities if v["risk"] == "CRITICAL"]
            high = [v for v in all_vulnerabilities if v["risk"] == "HIGH"]
            medium = [v for v in all_vulnerabilities if v["risk"] == "MEDIUM"]

            if critical:
                error(f"CRITICAL: {len(critical)} severe CORS misconfigurations")
                for c in critical:
                    result(f"  [{c['test']}]", f"{c['desc']} - ACAO: {c['acao']} Credentials: {c.get('acac','N/A')}")
            if high:
                warning(f"HIGH: {len(high)} high-risk CORS misconfigurations")
            if medium:
                info(f"MEDIUM: {len(medium)} medium-risk configurations")

            table_headers = ["Risk", "Test", "ACAO", "Credentials", "Details"]
            table_rows = []
            for v in all_vulnerabilities:
                table_rows.append([v["risk"], v["test"], v["acao"], v.get("acac", "N/A"), v["desc"][:40]])
            table(table_headers, table_rows[:20])

            result("Total CORS Issues", str(len(all_vulnerabilities)))
            result("Risk Score", f"{len(critical)*10 + len(high)*5 + len(medium)*2}/100")
        else:
            success("No CORS misconfigurations detected (limited to what's testable without auth)")

        return {"target": target, "vulnerabilities": all_vulnerabilities, "preflight_results": preflight_results}

    @staticmethod
    def test_preflight(target, scheme, domain, origin, acao, timeout, results):
        try:
            resp = requests.options(target, timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                    "Host": domain,
                })
            p_acao = resp.headers.get("Access-Control-Allow-Origin", "")
            p_acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            p_methods = resp.headers.get("Access-Control-Allow-Methods", "")
            p_headers = resp.headers.get("Access-Control-Allow-Headers", "")
            p_max_age = resp.headers.get("Access-Control-Max-Age", "")

            if p_acao:
                info(f"Preflight ACAO: {p_acao} | Methods: {p_methods} | Headers: {p_headers} | Max-Age: {p_max_age}")
                results.append({
                    "origin": origin, "acao": p_acao, "acac": p_acac,
                    "methods": p_methods, "headers": p_headers, "max_age": p_max_age,
                })
        except:
            pass

