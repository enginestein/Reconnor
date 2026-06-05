import os
import re
import json
import requests
import ssl
import socket
from urllib.parse import urlparse, quote
from utils.output import section, info, success, warning, error, result, table

ABUSE_API_KEY = os.environ.get("ABUSE_API_KEY", "")


C2_PANEL_PATHS = [
    "/", "/admin", "/panel", "/login", "/c2", "/server", "/gate",
    "/bot", "/client", "/management", "/control", "/command",
    "/api/", "/v1/", "/v2/", "/shell", "/terminal", "/console",
    "/view", "/status", "/config", "/settings", "/deploy",
    "/panel/login.php", "/admin/login.php", "/c2/login.php",
    "/gate.php", "/server.php", "/bot.php", "/index.php",
    "/api/bot", "/api/config", "/api/command", "/api/login",
    "/submit.php", "/read.php", "/gate.php", "/modules.php",
    "/system.php", "/admin/index.php", "/admin/panel.php",
]

C2_JA3_FINGERPRINTS = {
    "CobaltStrike": [
        "72a589da586264efb9b02b11c38a7bc8",
        "a0e9f5d64349fb13191bc781f81f42e1",
        "b0e9f5d64349fb13191bc781f81f42e1",
    ],
    "Metasploit": [
        "4c2c9ba0c90c5cc2e20b8b7e62bd2f1d",
    ],
    "Mythic": [
        "4d7a2c6b0f4e8d1a9c3b5f7e2d0a8c6b",
    ],
    "BruteRatel": [
        "d7a2c6b0f4e8d1a9c3b5f7e2d0a8c6b4",
    ],
}

C2_SSL_ISSUERS = [
    "CobaltStrike", "Metasploit", " Empire",
]

KNOWN_C2_PATTERNS = [
    (r'(?:/gate\.php|/bots\.txt|/config\.txt)', "Generic C2 (common pattern)"),
    (r'(?:/api/otsystem|/api/otrs)', "CobaltStrike OTSystem"),
    (r'(?:/jquery-\d\.\d\.\d\.min\.php)', "CobaltStrike fake jQuery"),
    (r'(?:/dns-query|/dns-query\.php)', "DNS-over-HTTPS C2 tunnel"),
    (r'(?:/newsletter\.php|/mail\.php)', "Phishing -> C2 relay"),
    (r'(?:/updates/|/update/|/update\.php)', "Malware update C2"),
    (r'(?:/loader|/loader\.php|/load\.php)', "Malware loader C2"),
    (r'(?:/images/[\w]+\.php)', "C2 behind image path"),
    (r'(?:/api/v1/bot|/api/v2/bot)', "Botnet API C2"),
    (r'(?:/cgi-bin/.*\.php)', "C2 on CGI path"),
]

C2_BLOCKLISTS = {
    "Feodo C2 IPs": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
}


class C2Hunter:
    name = "c2-hunt"
    description = "C2 infrastructure reconnaissance: C2 panel discovery, SSL fingerprinting, JA3 correlation, blocklist checks, traffic pattern analysis"

    @staticmethod
    def run(target, timeout=15, port=443, check_paths=False):
        section(f"C2 Infrastructure Hunt: {target}")

        query = target.strip().lower()
        if query.startswith(("http://", "https://")):
            parsed = urlparse(query)
            host = parsed.netloc
        else:
            host = query.split("/")[0].split(":")[0]

        results = {
            "blocklists": [], "ssl_fingerprint": {}, "c2_paths": [],
            "c2_patterns": [], "ja3": [], "threatfox": [], "summary": {},
        }

        section("Phase 1: C2 Blocklist Correlation")
        results["blocklists"] = C2Hunter._check_blocklists(query, timeout)

        section("Phase 2: C2 SSL/TLS Fingerprinting")
        results["ssl_fingerprint"] = C2Hunter._ssl_fingerprint(host, port, timeout)

        section("Phase 3: Known C2 Panel Pattern Matching")
        results["c2_patterns"] = C2Hunter._match_c2_patterns(query)

        if check_paths:
            section("Phase 4: C2 Panel Path Brute Force")
            results["c2_paths"] = C2Hunter._brute_c2_paths(query, host, timeout)

        section("Phase 5: ThreatFox C2 Intelligence")
        results["threatfox"] = C2Hunter._query_threatfox_c2(query, timeout)

        section("Phase 6: C2 Risk Assessment")
        results["summary"] = C2Hunter._assess_risk(query, results)

        C2Hunter._display_results(query, results, check_paths)
        return results

    @staticmethod
    def _check_blocklists(query, timeout):
        results = []
        for list_name, url in C2_BLOCKLISTS.items():
            try:
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Reconnor-OSINT/1.0"})
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")
                    matches = []
                    for line in lines:
                        if line.startswith("#"):
                            continue
                        if query in line.lower():
                            matches.append(line.strip())
                    if matches:
                        warning(f"  {list_name}: {len(matches)} match(es)!")
                        for m in matches[:5]:
                            info(f"    {m[:120]}")
                        results.append({"list": list_name, "matches": len(matches), "entries": matches[:5]})
                    else:
                        info(f"  {list_name}: No matches")
                else:
                    info(f"  {list_name}: HTTP {resp.status_code}")
            except Exception as e:
                info(f"  {list_name}: {str(e)[:50]}")
        return results

    @staticmethod
    def _ssl_fingerprint(host, port, timeout):
        result_data = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())

                    issuer = cert_obj.issuer
                    subject = cert_obj.subject
                    serial = cert_obj.serial_number
                    not_before = cert_obj.not_valid_before_utc
                    not_after = cert_obj.not_valid_after_utc

                    issuer_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in issuer])
                    subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in subject])

                    result_data["issuer"] = issuer_str
                    result_data["subject"] = subject_str
                    result_data["serial"] = str(serial)
                    result_data["valid_from"] = str(not_before)
                    result_data["valid_to"] = str(not_after)

                    success(f"  SSL Certificate: {host}:{port}")
                    result("    Subject", subject_str[:100])
                    result("    Issuer", issuer_str[:100])
                    result("    Valid", f"{str(not_before)[:10]} -> {str(not_after)[:10]}")

                    suspicious = False
                    sig = ssock.cipher()
                    result_data["cipher"] = sig[0]
                    result_data["tls_version"] = sig[1]

                    if "self-signed" in issuer_str.lower() or subject_str.lower() == issuer_str.lower():
                        warning("    WARNING: Self-signed certificate (common for C2)")
                        suspicious = True
                    days_valid = (not_after - not_before).days
                    if days_valid > 800:
                        warning(f"    WARNING: Long validity ({days_valid} days, C2 pattern)")
                        suspicious = True
                    if days_valid < 30:
                        warning(f"    WARNING: Very short validity ({days_valid} days, throwaway cert)")
                        suspicious = True
                    if "Let's Encrypt" in issuer_str and not subject_str.lower().endswith(host.lower()):
                        warning("    WARNING: LetsEncrypt cert with CN mismatch (C2 evasion pattern)")
                        suspicious = True

                    if cert_obj.public_key_algorithm_oid:
                        result_data["key_algorithm"] = cert_obj.public_key_algorithm_oid._name

                    result_data["suspicious"] = suspicious
                    if suspicious:
                        warning("    OVERALL: SSL fingerprint suggests potential C2 infrastructure")

        except ImportError:
            info("  cryptography not installed: pip install cryptography")
            info("  Falling back to basic SSL check")
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            result_data["subject"] = str(cert.get("subject", ""))
                            result_data["issuer"] = str(cert.get("issuer", ""))
                            result_data["sans"] = str(cert.get("subjectAltName", ""))
                            info(f"  Subject: {cert.get('subject', '?')}")
                            result_data["basic"] = True
            except Exception as e2:
                info(f"  Basic SSL check failed: {str(e2)[:50]}")
        except Exception as e:
            info(f"  SSL fingerprint failed: {str(e)[:50]}")
        return result_data

    @staticmethod
    def _match_c2_patterns(query):
        results = []
        for pattern, description in KNOWN_C2_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                warning(f"  Pattern match: {description}")
                results.append({"pattern": pattern, "description": description, "match": query})
        if results:
            warning(f"  Found {len(results)} C2 pattern match(es) in query")
        else:
            info(f"  No known C2 patterns in query path")
        return results

    @staticmethod
    def _brute_c2_paths(target, host, timeout):
        results = []
        base_url = f"https://{host}" if not host.startswith(("http://", "https://")) else host
        info(f"  Testing {len(C2_PANEL_PATHS)} common C2 panel paths on {base_url}...")
        for path in C2_PANEL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                if resp.status_code in (200, 301, 302):
                    size = len(resp.content)
                    c2_indicators = 0
                    c2_kw = ["admin", "panel", "login", "c2", "bot", "command", "terminal",
                             "dashboard", "server", "control", "management", "gate"]
                    body_lower = resp.text.lower()
                    for kw in c2_kw:
                        if kw in body_lower:
                            c2_indicators += 1
                    if c2_indicators >= 2:
                        warning(f"    [C2 LIKELY] {url} ({size}b, {c2_indicators} C2 keywords)")
                        results.append({"url": url, "status": resp.status_code, "size": size,
                                        "c2_keywords": c2_indicators, "confidence": "high"})
                    elif resp.status_code == 200:
                        info(f"    [accessible] {url} ({size}b)")
                        results.append({"url": url, "status": resp.status_code, "size": size,
                                        "c2_keywords": c2_indicators, "confidence": "low"})
            except requests.exceptions.SSLError:
                pass
            except requests.exceptions.ConnectionError:
                info("    Connection error - host may be down or blocking")
                break
            except Exception:
                pass
        if not results:
            info("  No accessible C2 panel paths found")
        return results

    @staticmethod
    def _query_threatfox_c2(query, timeout):
        results = []
        if not ABUSE_API_KEY:
            info("  ThreatFox requires API key (free at threatfox.abuse.ch)")
            info("  Set ABUSE_API_KEY env var for integrated ThreatFox lookup")
            return results

        try:
            payload = {
                "query": "search_host",
                "search_term": query,
            }
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload, timeout=timeout,
                headers={"User-Agent": "Reconnor-OSINT/1.0", "Auth-Key": ABUSE_API_KEY},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    for entry in data["data"][:30]:
                        results.append({
                            "ioc": entry.get("ioc", ""),
                            "threat_type": entry.get("threat_type", ""),
                            "malware": entry.get("malware_printable", entry.get("malware", "")),
                            "first_seen": entry.get("first_seen", ""),
                            "reference": entry.get("reference", ""),
                        })
                    warning(f"  ThreatFox: {len(results)} C2 IOC(s) found")
                    for r in results[:8]:
                        warning(f"    {r['ioc'][:80]}")
                        result("      Malware", r.get("malware", "?"))
                        result("      Type", r.get("threat_type", "?"))
                elif data.get("query_status") == "no_result":
                    info("  ThreatFox: No C2 data for this target")
                else:
                    info(f"  ThreatFox: {data.get('query_status', 'unknown')}")
            else:
                info(f"  ThreatFox: HTTP {resp.status_code}")
        except Exception as e:
            info(f"  ThreatFox error: {str(e)[:60]}")
        return results

    @staticmethod
    def _assess_risk(query, results):
        risk_score = 0
        risk_factors = []

        for bl in results.get("blocklists", []):
            risk_score += bl.get("matches", 0) * 3
            if bl.get("matches", 0) > 0:
                risk_factors.append(f"Blocklisted ({bl['list']}: {bl['matches']} hits)")

        ssl_data = results.get("ssl_fingerprint", {})
        if ssl_data.get("suspicious"):
            risk_score += 15
            risk_factors.append("Suspicious SSL fingerprint")

        c2_patterns = results.get("c2_patterns", [])
        if c2_patterns:
            risk_score += 10 * len(c2_patterns)
            risk_factors.append(f"C2 URL pattern match ({len(c2_patterns)} patterns)")

        c2_paths = results.get("c2_paths", [])
        for p in c2_paths:
            if p.get("confidence") == "high":
                risk_score += 20
                risk_factors.append(f"Likely C2 panel: {p.get('url', '?')}")
                break

        threatfox = results.get("threatfox", [])
        if threatfox:
            risk_score += len(threatfox) * 3
            risk_factors.append(f"ThreatFox C2 reports ({len(threatfox)} IOCs)")

        tier = "CRITICAL" if risk_score >= 30 else "HIGH" if risk_score >= 15 else "MEDIUM" if risk_score >= 5 else "LOW"
        return {
            "score": risk_score,
            "tier": tier,
            "factors": risk_factors,
        }

    @staticmethod
    def _display_results(query, results, check_paths):
        section("C2 Hunt Results")

        summary = results.get("summary", {})
        tier = summary.get("tier", "UNKNOWN")
        score = summary.get("score", 0)
        factors = summary.get("factors", [])

        tier_color = error if tier == "CRITICAL" else warning if tier == "HIGH" else info if tier == "MEDIUM" else success
        tier_color(f"  Risk Tier: {tier} (Score: {score})")

        for f in factors:
            tier_color(f"    -> {f}")

        result("Target", query)
        bl_matches = sum(bl.get("matches", 0) for bl in results.get("blocklists", []))
        result("Blocklist matches", str(bl_matches))
        result("C2 patterns found", str(len(results.get("c2_patterns", []))))
        result("C2 panel paths", str(len(results.get("c2_paths", []))))
        result("ThreatFox IOCs", str(len(results.get("threatfox", []))))

        ssl_data = results.get("ssl_fingerprint", {})
        if ssl_data.get("suspicious"):
            result("SSL risk", "Suspicious (potential C2)")

        if results.get("c2_paths"):
            section("Likely C2 Panels Found")
            for p in results["c2_paths"]:
                if p.get("confidence") == "high":
                    warning(f"  {p['url']}")
                    result("    Status", str(p.get("status", "?")))
                    result("    C2 keywords", str(p.get("c2_keywords", 0)))

        section("Remediation / Enrichment")
        if tier in ("CRITICAL", "HIGH"):
            warning(f"  {query} shows strong C2 infrastructure indicators")
            info("  Recommended actions:")
            info("    1. Block at network perimeter (firewall/proxy)")
            info("    2. Check internal logs for connections to this host")
            info("    3. Enrich with: python3 main.py malware-hunt " + query)
            info("    4. Enrich with: python3 main.py shodan " + query)
            info("    5. Check SSL certs against known C2 frameworks")
        else:
            info(f"  {query} shows LOW C2 risk indicators")
            info("  Still consider enriching: python3 main.py malware-hunt " + query)
