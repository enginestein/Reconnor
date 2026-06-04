import re
import requests
import socket
from urllib.parse import urlparse, quote
from utils.output import section, info, success, warning, error, result

AHMIA_API_URL = "https://ahmia.fi/search/?q={query}"
TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist"

KNOWN_ONION_DOMAINS = {
    "protonmail": "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
    "facebook": "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
    "duckduckgo": "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    "bbc news": "bbcnewsv2vjtpsuy.onion",
    "the intercept": "theintercept.s7qlyl25j6vq4h4yqnj7q7y2cwyk3w5f44wv6wqfhymy2z3q7f4bqid.onion",
    "nytimes": "nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion",
    "dw": "dwnewsv2vjtpsuy.onion",
    "cwt" : "cwtchim3z2wb4v3v5zle4s3szrc5tpefpnkkzcqpn6zhemkgz72p7yd.onion",
}

CLEARNET_ONION_DIRECTORIES = [
    "https://raw.githubusercontent.com/alecmuffett/onion-sites/master/onion-sites.txt",
    "https://raw.githubusercontent.com/OpenTechFellows/onionscan-results/master/onionscan_results.json",
]

DARKWEB_KEYWORDS = [
    "market", "forum", "drugs", "hack", "card", "counterfeit", "weapons",
    "passport", "license", "exploit", "shell", "trojan", "rat", "malware",
    "ransomware", "crypt", "bitcoin", "money", "fraud", "spam", "phish",
    "darknet", "darkweb", "hidden", "wikileaks", "leak", "dump",
]


class TorCheck:
    name = "tor-check"
    description = "Tor/dark web reconnaissance (.onion mirrors, exit nodes, dark web search)"

    @staticmethod
    def run(target, timeout=10):
        section(f"Tor & Dark Web Reconnaissance: {target}")

        domain = target.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split("/")[0].split(":")[0].lstrip("www.")

        results = {
            "tor_exit": False,
            "onion_mirrors": [],
            "dark_web_mentions": [],
            "ip_info": {},
            "known_onion_match": None,
        }

        section("Phase 1: Known .onion Services Lookup")
        known_match = None
        for key, onion_addr in KNOWN_ONION_DOMAINS.items():
            if key in domain or domain in key:
                known_match = onion_addr
                success(f"  Known .onion service matches '{domain}': http://{onion_addr}/")
                results["known_onion_match"] = {"name": key, "onion": onion_addr}
                break
        if not known_match:
            info(f"  No known .onion service matches '{domain}'")
            info(f"  Checking known .onion directory lists...")

        section("Phase 2: Clearnet + Dark Web Search")
        info(f"Searching for '{domain}' references across dark web sources...")

        ahmia_results = TorCheck._search_ahmia(domain, timeout)
        for r in ahmia_results:
            success(f"  [Ahmia] {r['title'][:60]}")
            info(f"    {r['url']}")
            results["dark_web_mentions"].append({"source": "Ahmia", "title": r["title"], "url": r["url"]})

        duck_results = TorCheck._search_duckduckgo_onion(domain, timeout)
        for r in duck_results:
            info(f"  [DuckDuckGo] {r['title'][:60]}")
            info(f"    {r['url']}")
            results["dark_web_mentions"].append({"source": "DuckDuckGo", "title": r["title"], "url": r["url"]})

        dir_results = TorCheck._search_onion_directories(domain, timeout)
        for r in dir_results:
            success(f"  [Onion Directory] Found matching .onion: http://{r['onion']}/")
            info(f"    Title: {r['title'][:60]}")
            results["dark_web_mentions"].append({"source": "OnionDir", "title": r["title"], "url": f"http://{r['onion']}/"})

        if not ahmia_results and not duck_results and not dir_results:
            info(f"  No dark web references found for '{domain}' on clearnet")
            info(f"  (Full dark web search requires Tor proxy on localhost:9050)")

        section("Phase 3: .onion Mirror Guess")
        if known_match:
            info(f"  Skipping guess phase — known .onion already found")
        else:
            candidates = list(set([
                f"{re.sub(r'[^a-zA-Z0-9]', '', domain)}.onion",
                f"{domain.split('.')[0]}.onion",
            ]))
            info(f"  Testing {len(candidates)} candidate .onion addresses...")
            info(f"  (requires Tor proxy on localhost:9050)")
            for c in candidates:
                url = f"http://{c}"
                info(f"    Trying: {url}")
                try:
                    proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
                    resp = requests.get(url, timeout=max(5, timeout),
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                        proxies=proxies)
                    if resp.status_code == 200:
                        success(f"    .onion FOUND: {url}")
                        results["onion_mirrors"].append({"url": url, "status": resp.status_code})
                        break
                except requests.exceptions.ConnectionError:
                    info(f"    Tor proxy not running — install: apt install tor && systemctl start tor")
                    break
                except TypeError as e:
                    if "socks" in str(e).lower():
                        info(f"    PySocks not installed — skipping .onion check")
                        info(f"    Install: pip install pysocks")
                        break
                    info(f"    {str(e)[:50]}")
                except Exception as e:
                    info(f"    {str(e)[:50]}")

        section("Phase 4: Tor Exit Node Check")
        info("Checking if target IP is a Tor exit node...")
        try:
            ip = socket.gethostbyname(domain)
            results["ip_info"]["ip"] = ip
            info(f"  Resolved: {domain} -> {ip}")
            try:
                resp = requests.get(TOR_EXIT_NODES_URL, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    exit_nodes = resp.text.strip().split("\n")
                    if ip in exit_nodes:
                        warning(f"  {ip} IS a Tor exit node!")
                        results["tor_exit"] = True
                    else:
                        success(f"  {ip} is NOT a Tor exit node")
                    results["ip_info"]["exit_node_count"] = len(exit_nodes)
            except Exception as e:
                info(f"  Could not fetch exit node list: {str(e)[:40]}")
        except socket.gaierror:
            error(f"  Could not resolve: {domain}")

        section("Phase 5: Tor Relay Check (Onionoo)")
        ip = results.get("ip_info", {}).get("ip", "")
        if ip:
            try:
                resp = requests.get(f"https://onionoo.torproject.org/details?search={ip}", timeout=timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    relays = data.get("relays", [])
                    if relays:
                        r = relays[0]
                        warning(f"  {ip} is a Tor relay: {r.get('nickname', '?')}")
                        result("  Nickname", r.get("nickname", "?"))
                        result("  Fingerprint", r.get("fingerprint", "?"))
                        result("  Country", r.get("country", "?"))
                        results["ip_info"]["tor_relay"] = True
                        results["ip_info"]["relay_name"] = r.get("nickname")
                    else:
                        info(f"  {ip} is not a Tor relay")
            except Exception as e:
                info(f"  Onionoo check failed: {str(e)[:40]}")

        section("Phase 6: Keyword Analysis")
        domain_lower = domain.lower()
        found_kw = [kw for kw in DARKWEB_KEYWORDS if kw in domain_lower]
        if found_kw:
            warning(f"  Domain contains dark web keywords: {found_kw}")
        else:
            info(f"  No dark web keywords in domain name")

        section("Tor & Dark Web Summary")
        result("Domain", domain)
        result("IP", results.get("ip_info", {}).get("ip", "N/A"))
        result("Tor exit node", "YES" if results.get("tor_exit") else "No")
        result("Tor relay", "YES" if results.get("ip_info", {}).get("tor_relay") else "No")
        known = results.get("known_onion_match")
        result("Known .onion match", f"http://{known['onion']}/" if known else "None")
        result("Dark web references", str(len(results["dark_web_mentions"])))

        if results["dark_web_mentions"]:
            section("Dark Web References Found")
            for i, m in enumerate(results["dark_web_mentions"][:5]):
                info(f"  {i+1}. [{m['source']}] {m.get('title','?')[:60]}")
                info(f"       {m.get('url','?')}")

        if not any([results["onion_mirrors"], results["dark_web_mentions"], known]):
            info("No dark web presence detected for this target")
            info("Tip: Use a Tor proxy for deeper .onion discovery")

        return results

    @staticmethod
    def _search_ahmia(query, timeout):
        results = []
        try:
            url = AHMIA_API_URL.format(query=quote(query))
            resp = requests.get(url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                no_js = "non-JavaScript" in resp.text or "notTorBrowser" in resp.text
                if no_js:
                    info(f"  [Ahmia] Requires Tor browser to serve results")
                    info(f"    Manual URL: {url}")
                    return results
                onion_links = re.findall(r'https?://([a-z2-7]{16,56}\.onion(?:/[^\s"<>]*)?)', resp.text)
                onion_links = [addr for addr in onion_links if "ahmia" not in addr and "juhanurmi" not in addr]
                onion_links = list(set(onion_links))
                if onion_links:
                    for addr in onion_links[:5]:
                        full_url = f"http://{addr}"
                        success(f"  [Ahmia] Found .onion: {full_url}")
                        results.append({"title": f"Ahmia result for '{query}'", "url": full_url})
                else:
                    info(f"  [Ahmia] No .onion results found")
        except Exception as e:
            info(f"  [Ahmia] {str(e)[:50]}")
        return results

    @staticmethod
    def _search_duckduckgo_onion(query, timeout):
        results = []
        try:
            search_queries = [
                f'"{query}" .onion',
                f'"{query}" hidden service tor',
                f'"{query}" dark web',
            ]
            for sq in search_queries:
                url = f"https://html.duckduckgo.com/html/?q={quote(sq)}"
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200:
                    links = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', resp.text)
                    for href, title in links:
                        title = re.sub(r'<[^>]+>', '', title).strip()
                        actual_url = TorCheck._decode_ddg_url(href)
                        if ".onion" in actual_url.lower() or any(kw in title.lower() for kw in ["tor", "dark", "hidden service", ".onion"]):
                            if not any(r["url"] == actual_url for r in results):
                                results.append({"title": title or actual_url, "url": actual_url})
                    if len(results) >= 5:
                        break
        except:
            pass
        return results[:5]

    @staticmethod
    def _decode_ddg_url(url):
        if "uddg=" in url:
            import urllib.parse
            m = re.search(r'uddg=([^&]+)', url)
            if m:
                try:
                    return urllib.parse.unquote(m.group(1))
                except:
                    pass
        return url

    @staticmethod
    def _search_onion_directories(query, timeout):
        results = []
        query_clean = query.replace(".", "").lower()
        for source_url in CLEARNET_ONION_DIRECTORIES[:1]:
            try:
                resp = requests.get(source_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")
                    for line in lines:
                        line = line.strip().lower()
                        if query_clean in line or query in line:
                            onion = re.search(r'([a-z2-7]{16,56}\.onion)', line)
                            if onion:
                                onion_addr = onion.group(1)
                                title = re.sub(r'http[^ ]*\.onion/?', '', line).strip() or line[:60]
                                results.append({"onion": onion_addr, "title": title})
            except:
                pass
        return results[:10]
