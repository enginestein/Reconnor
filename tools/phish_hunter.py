import re
import json
import requests
import hashlib
from urllib.parse import urlparse, quote
from utils.output import section, info, success, warning, error, result, table


PHISHING_INDICATORS = [
    "login", "signin", "account", "verify", "secure", "update",
    "confirm", "unlock", "validate", "authenticate", "password",
    "credential", "reset", "recover", "suspended", "restricted",
    "invoice", "payment", "banking", "paypal", "amazon", "apple",
    "microsoft", "google", "facebook", "instagram", "netflix",
    "chase", "wells fargo", "bank of america", "amex",
    "2fa", "mfa", "security", "alert", "unusual", "activity",
    "billing", "subscription", "refund", "claim", "reward",
]

PHISHING_KIT_PATTERNS = [
    (r'action=["\']?https?://[^"\']*@[^"\']+', "Credential exfil to external host"),
    (r'<input[^>]*type=["\']?hidden["\']?[^>]*value=["\']?[^"\']+@[^"\']+\.', "Hidden email field"),
    (r'base64_decode\s*\(\s*\$_[A-Z]+', "Base64 encoded payload in PHP"),
    (r'eval\s*\(\s*base64_decode', "Eval'd base64 backdoor"),
    (r'str_rot13|gzinflate|gzuncompress', "Obfuscated PHP payload"),
    (r'mail\s*\([^)]*@[^)]+', "PHP mail() to external address"),
    (r'https?://[^"\']+\.(ru|cn|xyz|tk|ml|ga|cf)\S*login', "Suspicious TLD in login path"),
    (r'<iframe[^>]*src=["\']https?://[^"\']+["\']', "External iframe injection"),
    (r'document\.write\s*\(unescape', "JS unescape obfuscation"),
]

PHISHING_DORKS = [
    "index of /phishing",
    "index of /phish",
    "index of /fishing",
    "phishing kit",
    "phish kit",
    "phishing script",
    "phishing template",
    "fake login",
    "fake page",
    "clone page",
    "email extractor",
    "mail extractor",
]

CREDS_PATTERNS = [
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*:.*[^\s]',
    r'(?:user|login|email).*:.*@',
    r'(?:password|passwd|pass).*:',
]


class PhishHunter:
    name = "phish-hunt"
    description = "Phishing infrastructure hunter: URLScan phishing hunting, phishing kit discovery, credential leak detection, cert transparency monitoring"

    @staticmethod
    def run(target, timeout=15, deep=False):
        section(f"Phishing Infrastructure Hunt: {target}")

        query = target.strip().lower()
        if query.startswith(("http://", "https://")):
            domain = urlparse(query).netloc
        else:
            domain = query.split("/")[0]

        results = {
            "urlscan": [], "certstream": [], "phishkits": [],
            "dorks": [], "indicators": [], "creds_leaked": [],
        }

        section("Phase 1: URLScan.io Phishing Search")
        results["urlscan"] = PhishHunter._search_urlscan_phish(query, domain, timeout, deep)

        section("Phase 2: Certificate Transparency - Suspicious Certs")
        results["certstream"] = PhishHunter._check_certstream(domain, timeout)

        section("Phase 3: Phishing Kit & Template Discovery")
        results["phishkits"] = PhishHunter._find_phish_kits(query, timeout)

        section("Phase 4: Indicator Analysis")
        results["indicators"] = PhishHunter._analyze_indicators(query, domain)

        if deep:
            section("Phase 5: Google Dorking for Phishing Infrastructure")
            results["dorks"] = PhishHunter._dork_phish(domain, timeout)

            section("Phase 6: Credential Leak Pattern Scan")
            results["creds_leaked"] = PhishHunter._scan_cred_leaks(domain, timeout)

        section("Phishing Risk Summary")
        PhishHunter._display_summary(query, domain, results)

        return results

    @staticmethod
    def _search_urlscan_phish(query, domain, timeout, deep):
        results = []
        query_types = [f"domain:{domain}"]
        query_types.append(f"domain:{domain} AND page.status:200")
        query_types.append(f"filename:{domain}")

        if not domain == query and len(query) > 4:
            query_types.append(f"{query}")

        seen_urls = set()
        for q in query_types[:3]:
            try:
                api_url = f"https://urlscan.io/api/v1/search/?q={quote(q)}&size={25 if deep else 15}"
                resp = requests.get(api_url, timeout=timeout,
                    headers={"User-Agent": "Reconnor-OSINT/1.0", "Accept": "application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total", 0)
                    scan_results = data.get("results", [])
                    if scan_results:
                        for entry in scan_results:
                            page = entry.get("page", {})
                            verdicts = entry.get("verdicts", {})
                            overall = verdicts.get("overall", {})
                            url = page.get("url", "")
                            if url and url not in seen_urls:
                                seen_urls.add(url)
                                is_malicious = overall.get("malicious", False)
                                score = overall.get("score", 0)
                                brand = verdicts.get("brands", [])
                                phish_info = {
                                    "url": url,
                                    "domain": page.get("domain", ""),
                                    "ip": page.get("ip", ""),
                                    "country": page.get("country", ""),
                                    "asn": page.get("asn", ""),
                                    "server": page.get("server", ""),
                                    "malicious": is_malicious,
                                    "score": score,
                                    "brands": [b.get("brand", "") for b in brand] if brand else [],
                                    "scan_id": entry.get("task", {}).get("uuid", ""),
                                    "time": entry.get("task", {}).get("time", ""),
                                }
                                results.append(phish_info)

                                if is_malicious:
                                    warning(f"  [PHISHING] {url[:90]}")
                                elif score > 30:
                                    info(f"  [suspicious] {url[:90]}")
                                if brand:
                                    info(f"    Brand spoofed: {', '.join(phish_info['brands'])}")
                                result("    IP", f"{page.get('ip', '?')} [{page.get('country', '?')}]")
                                result("    Score", str(score))
                        if total > len(scan_results):
                            info(f"    ({total} total results for this query)")
            except Exception as e:
                info(f"  URLScan query '{q[:30]}': {str(e)[:50]}")

        if results:
            malicious_count = sum(1 for r in results if r.get("malicious"))
            total_count = len(results)
            risk = "HIGH" if malicious_count > 0 else "MEDIUM" if total_count > 0 else "LOW"
            warning(f"  URLScan: {total_count} pages, {malicious_count} flagged phishing")
        else:
            info("  URLScan: No phishing results found")

        return results

    @staticmethod
    def _check_certstream(domain, timeout):
        results = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=timeout,
                headers={"User-Agent": "Reconnor-OSINT/1.0"},
            )
            if resp.status_code == 200:
                entries = resp.json()
                suspicious = []
                for entry in entries[:200]:
                    name_value = entry.get("name_value", "")
                    issuer = entry.get("issuer_name", "")
                    not_after = entry.get("not_after", "")
                    names = name_value.split("\n") if "\n" in name_value else [name_value]
                    for name in names:
                        name = name.strip().lower()
                        if "*." in name:
                            continue
                        if "phish" in name or "login" in name or "secure" in name or "verify" in name:
                            suspicious.append({
                                "name": name,
                                "issuer": issuer[:60],
                                "expiry": not_after[:10] if not_after else "?",
                            })
                            continue
                        sim_score = PhishHunter._domain_similarity(name, domain)
                        if sim_score > 0.7 and "." in name and name != domain and not name.endswith("." + domain):
                            suspicious.append({
                                "name": name, "issuer": issuer[:60],
                                "expiry": not_after[:10] if not_after else "?",
                                "similarity": sim_score,
                            })

                suspicious = PhishHunter._dedup_certs(suspicious)
                if suspicious:
                    warning(f"  crt.sh: {len(suspicious)} suspicious certificate(s)")
                    for s in suspicious[:10]:
                        sim_str = f" (sim: {s.get('similarity', 0):.0%})" if s.get("similarity") else ""
                        warning(f"    {s['name']}{sim_str}")
                        result("      Issuer", s.get("issuer", "?")[:50])
                        result("      Expiry", s.get("expiry", "?"))
                    results = suspicious[:15]
                else:
                    info(f"  crt.sh: No suspicious certs found")
            else:
                info(f"  crt.sh: HTTP {resp.status_code}")
        except Exception as e:
            info(f"  crt.sh error: {str(e)[:50]}")
        return results

    @staticmethod
    def _domain_similarity(a, b):
        if a == b:
            return 1.0
        a_clean = re.sub(r'[^a-zA-Z0-9]', '', a).lower()
        b_clean = re.sub(r'[^a-zA-Z0-9]', '', b).lower()
        if not a_clean or not b_clean:
            return 0.0
        shorter = min(len(a_clean), len(b_clean))
        matches = sum(1 for i in range(shorter) if a_clean[i] == b_clean[i])
        return matches / max(len(a_clean), len(b_clean))

    @staticmethod
    def _dedup_certs(certs):
        seen = set()
        deduped = []
        for c in certs:
            key = c.get("name", "")
            if key not in seen:
                seen.add(key)
                deduped.append(c)
        return deduped

    @staticmethod
    def _find_phish_kits(query, timeout):
        results = []

        section_sub = "  Searching for phishing kits and templates..."
        info(section_sub)

        kit_queries = [
            f'"{query}" "phishing kit"',
            f'"{query}" "fake login"',
            f'"{query}" "phish" script',
            f'"{query}" "clone" page',
        ]

        for q in kit_queries[:2]:
            for engine_url in [
                f"https://html.duckduckgo.com/html/?q={quote(q)}",
                f"https://www.google.com/search?q={quote(q)}",
            ]:
                try:
                    resp = requests.get(engine_url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    if resp.status_code == 200:
                        kit_matches = re.findall(r'(https?://[^\s"<>]+)', resp.text)
                        for kit_url in kit_matches[:5]:
                            if any(kw in kit_url.lower() for kw in ["phish", "kit", "fake", "clone", "template"]):
                                if query.lower() in kit_url.lower():
                                    info(f"    [Kit reference] {kit_url[:100]}")
                                    results.append({"url": kit_url, "source": "search"})
                except:
                    pass

        try:
            resp = requests.get(
                f"https://raw.githubusercontent.com/az0mb13/phishing-kit-tracker/main/kits.txt",
                timeout=timeout,
                headers={"User-Agent": "Reconnor-OSINT/1.0"},
            )
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    if query.lower() in line.lower():
                        warning(f"    [Known kit] {line.strip()[:100]}")
                        results.append({"url": line.strip(), "source": "kit-tracker"})
        except:
            pass

        if results:
            warning(f"  Found {len(results)} phishing kit reference(s)")
        else:
            info("  No phishing kit references found for this target")
        return results

    @staticmethod
    def _analyze_indicators(query, domain):
        results = []
        matched_indicators = []

        for indicator in PHISHING_INDICATORS:
            pattern = re.compile(re.escape(indicator), re.IGNORECASE)
            if pattern.search(query):
                matched_indicators.append(indicator)

        if domain:
            for indicator in PHISHING_INDICATORS:
                if indicator in domain:
                    matched_indicators.append(f"domain:{indicator}")

        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                          ".work", ".loan", ".download", ".review", ".date", ".men"]
        for tld in suspicious_tlds:
            if domain and domain.endswith(tld):
                matched_indicators.append(f"suspicious TLD: {tld}")

        leet_patterns = re.findall(r'[0-9]', domain)
        if len(leet_patterns) >= 3:
            matched_indicators.append("leet speak substitution in domain")

        domain_parts = domain.split(".") if domain else []
        known_brands = ["paypal", "amazon", "google", "facebook", "microsoft", "apple",
                        "netflix", "instagram", "chase", "wellsfargo", "bankofamerica",
                        "amex", "dropbox", "adobe", "linkedin", "twitter", "whatsapp"]
        for brand in known_brands:
            if brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
                if not domain.endswith(".com") or domain.count(".") > 1:
                    matched_indicators.append(f"brand impersonation: {brand}")

        if matched_indicators:
            warning(f"  Phishing indicators detected: {len(matched_indicators)}")
            for ind in matched_indicators[:10]:
                warning(f"    -> {ind}")
            results = matched_indicators
        else:
            info("  No strong phishing indicators in query")
        return results

    @staticmethod
    def _dork_phish(domain, timeout):
        results = []
        dork_queries = [
            f'site:{domain} "login" "password"',
            f'site:{domain} "email" "password" input',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:verify',
            f'site:{domain} inurl:secure',
            f'site:{domain} "action=" "mail"',
            f'site:{domain} "base64_decode"',
            f'site:{domain} "eval("',
        ]
        for dork in dork_queries:
            try:
                url = f"https://www.google.com/search?q={quote(dork)}"
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200:
                    if "did not match" not in resp.text and len(resp.text) > 1000:
                        info(f"  Dork: {dork[:50]}... -> results found")
                        results.append({"dork": dork, "found": True})
                    else:
                        info(f"  Dork: {dork[:50]}... -> no results")
                        results.append({"dork": dork, "found": False})
            except:
                pass
        found_count = sum(1 for r in results if r.get("found"))
        if found_count:
            warning(f"  Dorking: {found_count}/{len(results)} queries returned results")
        else:
            info("  Dorking: No exposed pages found")
        return results

    @staticmethod
    def _scan_cred_leaks(domain, timeout):
        results = []
        try:
            paste_search_url = f"https://www.google.com/search?q=site:pastebin.com+{quote(domain)}+password+OR+login"
            resp = requests.get(paste_search_url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                found_urls = re.findall(r'(https?://pastebin\.com/[^\s"<>]+)', resp.text)
                if found_urls:
                    warning(f"  Found {len(found_urls)} potential credential leak(s) on paste sites!")
                    results.extend([{"source": "pastebin", "url": u} for u in found_urls[:5]])
                    for u in found_urls[:5]:
                        warning(f"    {u}")
        except:
            pass

        try:
            resp = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}+AND+filename:log+OR+filename:txt+OR+filename:csv",
                timeout=timeout,
                headers={"User-Agent": "Reconnor-OSINT/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("results", [])[:5]:
                    page = entry.get("page", {})
                    url = page.get("url", "")
                    if url and "log" in url.lower():
                        info(f"  Potential log exposure: {url[:90]}")
                        results.append({"source": "urlscan", "url": url})
        except:
            pass

        if results:
            warning(f"  Total credential leak findings: {len(results)}")
        return results

    @staticmethod
    def _display_summary(query, domain, results):
        urlscan_phish = sum(1 for r in results.get("urlscan", []) if r.get("malicious"))
        urlscan_total = len(results.get("urlscan", []))
        suspicious_certs = len(results.get("certstream", []))
        phish_kits = len(results.get("phishkits", []))
        indicators = len(results.get("indicators", []))
        creds = len(results.get("creds_leaked", []))

        result("Target", domain)
        result("URLScan phishing pages", f"{urlscan_phish}/{urlscan_total}")
        result("Suspicious certificates", str(suspicious_certs))
        result("Phishing kit references", str(phish_kits))
        result("Phishing indicators", str(indicators))
        result("Credential leaks", str(creds))

        risk_score = 0
        risk_factors = []
        if urlscan_phish > 0:
            risk_score += 25
            risk_factors.append(f"{urlscan_phish} phishing pages on URLScan")
        if suspicious_certs > 0:
            risk_score += 15
            risk_factors.append(f"{suspicious_certs} suspicious certificates")
        if phish_kits > 0:
            risk_score += 20
            risk_factors.append(f"{phish_kits} phishing kit references")
        if indicators > 3:
            risk_score += 10
            risk_factors.append(f"{indicators} phishing indicators")
        if creds > 0:
            risk_score += 15
            risk_factors.append(f"{creds} potential credential leaks")

        tier = "CRITICAL" if risk_score >= 30 else "HIGH" if risk_score >= 15 else "MEDIUM" if risk_score >= 5 else "LOW"
        tier_color = error if tier == "CRITICAL" else warning if tier == "HIGH" else info if tier == "MEDIUM" else success
        tier_color(f"  Phishing Risk: {tier} (Score: {risk_score})")
        for f in risk_factors:
            tier_color(f"    -> {f}")

        section("Hunting Recommendations")
        if risk_score > 0:
            info("  Enrichment pipeline:")
            info(f"    1. python3 main.py malware-hunt {domain}")
            info(f"    2. python3 main.py c2-hunt {domain}")
            info(f"    3. python3 main.py shodan {domain}")
            info(f"    4. python3 main.py dns {domain}")
            info(f"    5. python3 main.py whois {domain}")
            info("  URLScan deep scans:")
            for r in results.get("urlscan", [])[:3]:
                if r.get("scan_id"):
                    info(f"    https://urlscan.io/result/{r['scan_id']}/")
        else:
            info(f"  No immediate phishing infrastructure detected for {domain}")
            info("  Recommended baseline monitoring:")
            info(f"    python3 main.py certsearch {domain}")
            info(f"    python3 main.py pastewatch {domain}")
