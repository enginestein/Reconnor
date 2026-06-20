import re
import dns.resolver
import dns.exception
from utils.output import section, info, success, warning, error, result, table


class EmailSecurity:
    name = "email-security"
    description = "Email security analyzer (SPF, DKIM, DMARC, MX, and security scoring)"

    @staticmethod
    def run(target, selector="default", timeout=10):
        section(f"Email Security Analyzer: {target}")

        results = {
            "target": target,
            "mx_records": [],
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "security_score": None,
            "issues": [],
        }

        # MX Records
        info("Checking MX records...")
        mx_records = EmailSecurity._resolve_mx(target, timeout)
        if mx_records:
            results["mx_records"] = mx_records
            for mx in mx_records[:5]:
                result("MX", f"{mx['exchange']} (priority {mx['priority']})")
        else:
            warning("No MX records found - domain cannot receive email")

        # SPF Record
        info("Checking SPF record...")
        spf = EmailSecurity._resolve_spf(target, timeout)
        if spf:
            results["spf"] = spf
            result("SPF", spf.get("raw", "N/A"))
            if spf.get("pass_all"):
                warning("SPF: +all (pass all) - any server can send email as this domain")
                results["issues"].append("SPF pass-all (+all) allows any sender")
            elif spf.get("fail_all"):
                success("SPF: -all (fail all) - properly restricted")
            elif spf.get("neutral_all"):
                warning("SPF: ~all or ?all - soft fail/neutral, not fully protected")
                results["issues"].append("SPF soft fail/neutral (~all/?all)")
            if spf.get("redirect"):
                info(f"SPF redirect: {spf['redirect']}")
            if spf.get("includes"):
                info(f"SPF includes: {', '.join(spf['includes'])}")
        else:
            warning("No SPF record found - domain is vulnerable to email spoofing")
            results["issues"].append("No SPF record - vulnerable to spoofing")

        # DKIM Record
        info(f"Checking DKIM record (selector: {selector})...")
        dkim = EmailSecurity._resolve_dkim(target, selector, timeout)
        if dkim:
            results["dkim"] = dkim
            result("DKIM", dkim.get("raw", "N/A")[:100])
            success(f"DKIM found with selector '{selector}'")
        else:
            common_selectors = ["google", "google._domainkey", "dkim", "mail", "default", "selector1", "selector2", "protonmail", "s1", "s2", "mx"]
            dkim_found = False
            for alt_sel in common_selectors:
                if alt_sel == selector:
                    continue
                alt_dkim = EmailSecurity._resolve_dkim(target, alt_sel, timeout)
                if alt_dkim:
                    results["dkim"] = alt_dkim
                    results["dkim_selector"] = alt_sel
                    result("DKIM", f"Found with selector '{alt_sel}': {alt_dkim.get('raw', 'N/A')[:100]}")
                    success(f"DKIM found with selector '{alt_sel}'")
                    dkim_found = True
                    break
            if not dkim_found:
                warning("No DKIM record found - emails may not be digitally signed")
                results["issues"].append("No DKIM record found")

        # DMARC Record
        info("Checking DMARC record...")
        dmarc = EmailSecurity._resolve_dmarc(target, timeout)
        if dmarc:
            results["dmarc"] = dmarc
            result("DMARC", dmarc.get("raw", "N/A"))
            policy = dmarc.get("policy", "none")
            if policy == "reject":
                success(f"DMARC policy: reject (strong protection)")
            elif policy == "quarantine":
                warning(f"DMARC policy: quarantine (moderate protection)")
            elif policy == "none":
                warning(f"DMARC policy: none (monitoring only, no enforcement)")
                results["issues"].append("DMARC policy is 'none' - no enforcement")
            if dmarc.get("pct"):
                info(f"DMARC applies to {dmarc['pct']}% of emails")
            if dmarc.get("rua"):
                info(f"DMARC reports sent to: {dmarc['rua']}")
        else:
            warning("No DMARC record found - no email authentication policy")
            results["issues"].append("No DMARC record found")

        # Calculate security score
        score_details = []
        score = 100

        if not spf:
            score -= 30
            score_details.append("-30: No SPF")
        elif spf.get("pass_all"):
            score -= 15
            score_details.append("-15: SPF +all")

        if not results.get("dkim"):
            score -= 25
            score_details.append("-25: No DKIM")

        if not dmarc:
            score -= 30
            score_details.append("-30: No DMARC")
        elif dmarc.get("policy") == "none":
            score -= 15
            score_details.append("-15: DMARC policy=none")
        elif dmarc.get("policy") == "quarantine":
            score -= 5
            score_details.append("-5: DMARC policy=quarantine")

        if not mx_records:
            score -= 15
            score_details.append("-15: No MX records")

        score = max(0, min(100, score))
        results["security_score"] = {"score": score, "details": score_details}

        grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
        result("Security Score", f"{score}/100 (Grade {grade})")

        if score == 100:
            success("Excellent email security configuration")
        elif score >= 70:
            info("Good email security, minor improvements possible")
        elif score >= 40:
            warning("Moderate email security - improvements recommended")
        else:
            error("Poor email security - significant improvements needed")

        if results["issues"]:
            section("Issues Found")
            for issue in results["issues"]:
                error(issue)

        return results

    @staticmethod
    def _resolve_mx(domain, timeout):
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
            records = []
            for rdata in answers:
                exchange = str(rdata.exchange).rstrip(".")
                if exchange:
                    records.append({"exchange": exchange, "priority": rdata.preference})
            records.sort(key=lambda x: x["priority"])
            return records
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.DNSException:
            return []

    @staticmethod
    def _resolve_spf(domain, timeout):
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings).strip()
                if txt.startswith("v=spf1"):
                    spf_data = {"raw": txt}
                    spf_data["pass_all"] = "+all" in txt
                    spf_data["fail_all"] = "-all" in txt
                    spf_data["neutral_all"] = "~all" in txt or "?all" in txt
                    includes = re.findall(r'include:(\S+)', txt)
                    spf_data["includes"] = includes if includes else []
                    redirect = re.findall(r'redirect=(\S+)', txt)
                    spf_data["redirect"] = redirect[0] if redirect else None
                    return spf_data
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.DNSException:
            return None

    @staticmethod
    def _resolve_dkim(domain, selector, timeout):
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=timeout)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings).strip()
                if "v=DKIM1" in txt:
                    return {"raw": txt, "selector": selector}
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.DNSException:
            return None

    @staticmethod
    def _resolve_dmarc(domain, timeout):
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=timeout)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings).strip()
                if txt.startswith("v=DMARC1"):
                    dmarc_data = {"raw": txt}
                    policy = re.findall(r'p=(\S+)', txt)
                    dmarc_data["policy"] = policy[0] if policy else "none"
                    pct = re.findall(r'pct=(\d+)', txt)
                    dmarc_data["pct"] = int(pct[0]) if pct else None
                    rua = re.findall(r'rua=mailto:(\S+)', txt)
                    dmarc_data["rua"] = rua[0] if rua else None
                    ruf = re.findall(r'ruf=mailto:(\S+)', txt)
                    dmarc_data["ruf"] = ruf[0] if ruf else None
                    sp = re.findall(r'sp=(\S+)', txt)
                    dmarc_data["subdomain_policy"] = sp[0] if sp else None
                    return dmarc_data
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.DNSException:
            return None
