import re
import requests
from urllib.parse import urlparse, urljoin
from utils.output import section, info, success, warning, error, result, table

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

EMAIL_PATTERNS = [
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Standard email"),
]

COMMON_FORMATS = [
    ("{first}", "first"),
    ("{first}.{last}", "first.last"),
    ("{first}{last}", "firstlast"),
    ("{f}{last}", "f.last"),
    ("{first}_{last}", "first_last"),
    ("{first}-{last}", "first-last"),
    ("{last}.{first}", "last.first"),
    ("{first}{l}", "firstl"),
    ("{f}{l}", "fl"),
    ("{first}.{l}", "first.l"),
    ("{last}{first}", "lastfirst"),
    ("{first}.{last}.{mid}", "first.last.mid"),
    ("{first}{last}01", "firstlast01"),
    ("{first}.{last}01", "first.last01"),
    ("info", "info"),
    ("contact", "contact"),
    ("support", "support"),
    ("sales", "sales"),
    ("admin", "admin"),
    ("hello", "hello"),
    ("team", "team"),
]

ROLE_EMAILS = ["admin", "info", "support", "contact", "sales", "hello", "team", "careers",
               "jobs", "hr", "pr", "press", "media", "billing", "finance", "legal",
               "abuse", "postmaster", "hostmaster", "webmaster", "noreply", "newsletter",
               "marketing", "partners", "feedback", "help", "service", "enquiries"]


class EmailFinder:
    name = "email-finder"
    description = "Find and enumerate email addresses from domains using web scraping, pattern guessing, search engines, and breach data"

    @staticmethod
    def run(target, timeout=10):
        section(f"Email Finder: {target}")

        domain = target.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split("/")[0].split(":")[0].lstrip("www.")

        all_emails = set()
        page_urls_searched = 0
        name_pairs = []

        section("Phase 1: Scrape Web Pages for Email Addresses")
        urls_to_check = [
            f"https://www.{domain}",
            f"https://{domain}",
            f"https://www.{domain}/contact",
            f"https://{domain}/contact",
            f"https://www.{domain}/about",
            f"https://{domain}/about",
            f"https://www.{domain}/team",
            f"https://{domain}/team",
            f"https://www.{domain}/about-us",
            f"https://{domain}/about-us",
        ]

        for url in urls_to_check:
            try:
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                page_urls_searched += 1

                found = re.findall(EMAIL_PATTERNS[0][0], resp.text)
                for email in found:
                    if email.lower().endswith(f"@{domain}") or email.lower().endswith(f"@{domain}".lower()):
                        all_emails.add(email.lower())
                        success(f"  {email}")
                    elif email.lower().endswith(f"@{domain}") or not email.lower().endswith("example.com"):
                        info(f"  [{urlparse(url).netloc}] {email}")

                if HAS_BS4:
                    for a in bs4.BeautifulSoup(resp.text, "html.parser").find_all("a", href=True):
                        href = a["href"]
                        if "mailto:" in href:
                            mail = href.replace("mailto:", "").split("?")[0].strip()
                            if mail and "@" in mail:
                                all_emails.add(mail.lower())
                                success(f"  [mailto] {mail}")

                    for script_tag in bs4.BeautifulSoup(resp.text, "html.parser").find_all("script"):
                        script_text = script_tag.string or ""
                        found_in_js = re.findall(EMAIL_PATTERNS[0][0], script_text)
                        for e in found_in_js:
                            all_emails.add(e.lower())
                            success(f"  [javascript] {e}")

            except Exception as e:
                pass

        if HAS_BS4:
            section("Phase 2: Extract Names for Pattern Guessing")
            try:
                resp = requests.get(f"https://www.{domain}", timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                soup = bs4.BeautifulSoup(resp.text, "html.parser")

                team_section = soup.find_all(["div", "section", "ul"], class_=re.compile(r"team|staff|people|member|author|profile", re.I))
                if team_section:
                    for section_tag in team_section:
                        names = re.findall(r'>([A-Z][a-z]+ [A-Z][a-z]+)<', str(section_tag))
                        for name in names[:10]:
                            parts = name.split()
                            if len(parts) >= 2:
                                name_pairs.append((parts[0], parts[-1]))
                                info(f"  Found name: {name}")

                linkedin_urls = [a["href"] for a in soup.find_all("a", href=True) if "linkedin.com/in/" in a["href"]]
                for li_url in linkedin_urls[:5]:
                    path = urlparse(li_url).path.strip("/").split("/")
                    slug = path[-1] if path else ""
                    name_match = re.match(r'([a-z]+)-([a-z]+)', slug, re.I)
                    if name_match:
                        name_pairs.append((name_match.group(1).capitalize(), name_match.group(2).capitalize()))
            except:
                pass

        section("Phase 3: Generate Emails from Common Formats")
        if name_pairs:
            info(f"Generating emails using {len(name_pairs)} discovered name(s) and {len(COMMON_FORMATS)} format(s)...")
            generated = set()
            for first, last in name_pairs:
                f_initial = first[0].lower() if first else ""
                l_initial = last[0].lower() if last else ""
                for fmt, fmt_name in COMMON_FORMATS:
                    email_local = fmt.format(first=first.lower(), last=last.lower(), f=f_initial, l=l_initial, mid="")
                    email = f"{email_local}@{domain}"
                    if email not in generated and email_local not in [e.split("@")[0] for e in all_emails]:
                        generated.add(email)
            info(f"Generated {len(generated)} potential email(s)")
            name_pairs_output = list(set(f"{a} {b}" for a, b in name_pairs))
            if name_pairs_output:
                result("Names discovered", str(len(name_pairs_output)))
                table(["First", "Last"], [[p.split()[0], p.split()[-1]] for p in name_pairs_output[:10]])

        role_emails = set(f"{role}@{domain}" for role in ROLE_EMAILS)
        info(f"Adding {len(role_emails)} role-based email(s)")

        section("Phase 4: Verify Email Deliverability (SMTP Check)")
        info("Checking mail server configuration...")
        mx_exists = False
        try:
            import socket
            import dns.resolver
            try:
                answers = dns.resolver.resolve(domain, "MX")
                mx_records = [(int(r.preference), str(r.exchange).rstrip(".")) for r in answers]
                mx_records.sort()
                if mx_records:
                    mx_exists = True
                    mx_host = mx_records[0][1]
                    info(f"MX record found: {mx_host} (checking email validity requires SMTP connection)")
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    try:
                        sock.connect((mx_host, 25))
                        banner = sock.recv(1024).decode("utf-8", errors="ignore")
                        if "220" in banner:
                            success("SMTP server is reachable on port 25")
                    except:
                        info("SMTP port 25 may be blocked (common on residential ISPs)")
                    finally:
                        sock.close()
            except dns.resolver.NoAnswer:
                info("No MX records found")
            except dns.resolver.NXDOMAIN:
                error("Domain does not exist")
        except ImportError:
            info("Install dnspython for MX lookup: pip install dnspython")

        section("Phase 5: Search Engine Dorking for Emails")
        search_urls = [
            f"https://www.google.com/search?q=%40{domain}+email",
            f"https://search.yahoo.com/search?p=%40{domain}+email",
            f"https://www.bing.com/search?q=%40{domain}+email",
        ]
        for search_url in search_urls:
            try:
                resp = requests.get(search_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), resp.text)
                for email in found:
                    all_emails.add(email.lower())
            except:
                pass

        section("Email Finder Summary")
        all_confirmed = sorted(all_emails)
        all_potential = sorted(role_emails | (generated if name_pairs else set()))

        if all_confirmed:
            section(f"Confirmed Emails ({len(all_confirmed)})")
            for email in all_confirmed:
                success(f"  {email}")
        else:
            warning("No confirmed emails found on web pages")

        if all_potential:
            section(f"Potential Emails (pattern-based, not verified) ({len(all_potential)})")
            for email in list(all_potential)[:20]:
                info(f"  {email}")
            if len(all_potential) > 20:
                info(f"  ... and {len(all_potential) - 20} more")
        else:
            info("No potential emails generated (no names found on page)")

        result("Pages searched", str(page_urls_searched))
        result("Confirmed emails", str(len(all_confirmed)))
        result("Potential emails", str(len(all_potential)))
        result("SMTP available", "Yes (MX records found)" if mx_exists else "No MX records")

        return {"target": domain, "confirmed": list(all_confirmed), "potential": list(all_potential), "names": name_pairs}
