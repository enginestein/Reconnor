import requests
import re
from urllib.parse import urljoin, urlparse
from utils.output import section, info, success, warning, error, result, table

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

def fetch_text(url, timeout=15):
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        warning(f"Could not fetch {url}: {e}")
    return None

def parse_robots_txt(text):
    parsed = {"user_agents": {}, "sitemaps": [], "crawl_delay": {}, "disallowed": {}, "allowed": {}}
    current_ua = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r'^(User-agent|Disallow|Allow|Sitemap|Crawl-Delay|Host):\s*(.*)', stripped, re.IGNORECASE)
        if not match:
            continue
        directive, value = match.group(1).lower(), match.group(2).strip()
        if directive == "user-agent":
            current_ua = value.lower() if value else "*"
        elif directive == "disallow":
            if current_ua:
                parsed["disallowed"].setdefault(current_ua, []).append(value if value else "/")
        elif directive == "allow":
            if current_ua:
                parsed["allowed"].setdefault(current_ua, []).append(value)
        elif directive == "sitemap":
            parsed["sitemaps"].append(value)
        elif directive == "crawl-delay":
            if current_ua:
                try:
                    parsed["crawl_delay"][current_ua] = float(value)
                except ValueError:
                    pass
        elif directive == "host":
            parsed.setdefault("host", value)
    return parsed

class RobotsAnalyzer:
    name = "robots"
    description = "Analyze robots.txt and sitemap.xml for recon"

    @staticmethod
    def run(target, ollama_model=None):
        section(f"Robots.txt & Sitemap Analyzer: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed_url = urlparse(target)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        robots_url = urljoin(base, "/robots.txt")
        info(f"Fetching {robots_url}...")
        robots_text = fetch_text(robots_url)

        if not robots_text:
            error("No robots.txt found (or access denied)")
        else:
            result("robots.txt", f"Found ({len(robots_text)} bytes)")
            parsed = parse_robots_txt(robots_text)

            section("Sitemaps")
            if parsed["sitemaps"]:
                for s in parsed["sitemaps"]:
                    success(s)
            else:
                info("No sitemaps specified in robots.txt")

            for ua, paths in parsed["disallowed"].items():
                if ua == "*" or ua == "googlebot" or ua == "bingbot":
                    label = "Googlebot" if ua == "googlebot" else "Bingbot" if ua == "bingbot" else "All bots"
                    if paths:
                        section(f"Disallowed Paths ({label} — {len(paths)})")
                        for p in paths:
                            if p and p != "/":
                                warning(p)
                            elif p == "/":
                                info("All paths disallowed — site does not want crawling")

            if parsed["crawl_delay"]:
                section("Crawl Delay")
                for ua, delay in parsed["crawl_delay"].items():
                    result(ua, f"{delay}s")

            if ollama_model:
                try:
                    from utils.ollama_helper import OllamaHelper
                    ollama = OllamaHelper(model=ollama_model)
                    if ollama.available:
                        info("AI analysis of robots.txt...")
                        ai_output = ollama.analyze_robots_txt(parsed, base)
                        section("AI Analysis")
                        print(ai_output)
                except Exception as e:
                    warning(f"AI analysis unavailable: {e}")

        section("Sitemaps Exploration")
        found_sitemaps = []

        if robots_text:
            parsed_robots = parse_robots_txt(robots_text)
            found_sitemaps.extend(parsed_robots["sitemaps"])

        sitemap_url = urljoin(base, "/sitemap.xml")
        if sitemap_url not in found_sitemaps:
            sitemap_content = fetch_text(sitemap_url)
            if sitemap_content:
                found_sitemaps.append(sitemap_url)
                section("Sitemap Index / URLs")

                sitemap_urls = re.findall(r'<loc>(.*?)</loc>', sitemap_content, re.IGNORECASE)
                sitemap_links = re.findall(r'<sitemap>(.*?)</sitemap>', sitemap_content, re.IGNORECASE)
                sub_sitemaps = re.findall(r'<loc>(.*?)</loc>', '\n'.join(sitemap_links), re.IGNORECASE) if sitemap_links else []

                if sub_sitemaps:
                    info(f"Found {len(sub_sitemaps)} sub-sitemaps")
                    for s in sub_sitemaps[:20]:
                        result("Sub-sitemap", s)
                    if len(sub_sitemaps) > 20:
                        info(f"... and {len(sub_sitemaps) - 20} more")

                discovered_urls = []
                for sitemap_file in [sitemap_url] + sub_sitemaps:
                    content = fetch_text(sitemap_file)
                    if content:
                        urls_found = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
                        discovered_urls.extend(urls_found)

                if discovered_urls:
                    info(f"Total URLs in sitemap: {len(discovered_urls)}")
                    section("Sample URLs from Sitemap")
                    for u in discovered_urls[:30]:
                        success(u)
                    if len(discovered_urls) > 30:
                        info(f"... and {len(discovered_urls) - 30} more URLs")

                    if ollama_model:
                        try:
                            from utils.ollama_helper import OllamaHelper
                            ollama = OllamaHelper(model=ollama_model)
                            if ollama.available:
                                info("AI analysis of sitemap URLs...")
                                ai_output = ollama.analyze_sitemap_urls(discovered_urls)
                                section("AI Sitemap Analysis")
                                print(ai_output)
                        except Exception as e:
                            warning(f"AI sitemap analysis unavailable: {e}")
                else:
                    info("Sitemap found but no URLs extracted")

        section("Recon Insights")

        sensitive_paths = [
            "/admin/", "/wp-admin/", "/login/", "/config/", "/backup/",
            ".env", ".git/config", "phpinfo.php", "/server-status"
        ]

        sensitive_allowed = []
        for path in sensitive_paths:
            test_url = urljoin(base, path)
            try:
                r = requests.get(test_url, timeout=10, headers={"User-Agent": USER_AGENT})
                if r.status_code == 200:
                    sensitive_allowed.append((path, r.status_code, len(r.content)))
            except Exception:
                pass

        sensitive_disallowed = []
        if robots_text:
            parsed_robots = parse_robots_txt(robots_text)
            for ua, paths in parsed_robots["disallowed"].items():
                for p in paths:
                    if any(kw in p.lower() for kw in ["admin", "login", "config", "backup", "wp-admin", "env", "git"]):
                        if (p, ua) not in sensitive_disallowed:
                            sensitive_disallowed.append((p, ua))

        if sensitive_disallowed:
            warning("Sensitive paths explicitly hidden in robots.txt — potential recon targets:")
            for path, ua in sensitive_disallowed:
                warning(f"  {path} (blocked for {ua})")

        if sensitive_allowed:
            info("Sensitive paths accessible (not blocked):")
            for path, status, size in sensitive_allowed:
                info(f"  {path} -> HTTP {status} ({size} bytes)")

        return {"target": target, "robots": robots_text is not None, "sitemaps": found_sitemaps}
