import re
import requests
import urllib3
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

PASTEBIN_SEARCH = "https://psbdmp.ws/api/search/{query}"
PSBDMP_SEARCH_V2 = "https://psbdmp.ws/api/search/{query}"
PSBDMP_SEARCH_V3 = "https://psbdmp.ws/api/v3/search/{query}"
PASTEBIN_DIRECT = "https://pastebin.com/raw/{paste_id}"

PASTE_SITES = [
    ("Pastebin", "https://pastebin.com/search?q={query}"),
    ("Pastebin (raw)", "https://pastebin.com/raw/{paste_id}"),
    ("Paste.ee", "https://paste.ee/search?q={query}"),
    ("Paste.ee RSS", "https://paste.ee/rss"),
    ("Hastebin", "https://hastebin.com/search?q={query}"),
    ("Ghostbin", "https://ghostbin.com/search?q={query}"),
    ("Rentry", "https://rentry.co/search/?q={query}"),
    ("Doxbin", "https://doxbin.org/search?q={query}"),
    ("Leaked.wiki", "https://leaked.wiki/search?q={query}"),
    ("Snippet.host", "https://snippet.host"),
    ("Controlc", "https://controlc.com"),
]

RECENT_PASTES = [
    "https://pastebin.com/archive",
    "https://psbdmp.ws/api/v3/recent",
]


class PasteWatch:
    name = "pastewatch"
    description = "Pastebin and code snippet monitoring: search for emails, domains, keywords across paste sites, monitor recent pastes"

    @staticmethod
    def run(target, timeout=10):
        section(f"Paste & Code Snippet Monitor: {target}")

        query = target.strip()
        all_results = {"pastebin": [], "psbdmp": [], "mentions": [], "recent": []}

        is_email = bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query))
        is_domain = bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query)) and not is_email

        result("Search Query", query)
        result("Query Type", "Email" if is_email else "Domain" if is_domain else "Keyword")
        info(f"Searching paste sites for: {query}")

        section(f"Phase 1: Pastebin Search")
        try:
            resp = requests.get(
                f"https://pastebin.com/search?q={quote(query)}", timeout=timeout,
                headers=HEADERS, verify=False,
            )
            if resp.status_code == 200:
                paste_links = re.findall(r'/raw/([a-zA-Z0-9]{8})', resp.text)
                paste_links = list(set(paste_links))
                if paste_links:
                    warning(f"  Found {len(paste_links)} paste(s) on Pastebin!")
                    for pid in paste_links[:10]:
                        raw_url = f"https://pastebin.com/raw/{pid}"
                        try:
                            raw_resp = requests.get(
                                raw_url, timeout=timeout,
                                headers=HEADERS, verify=False,
                            )
                            content = raw_resp.text[:500]
                            size = len(raw_resp.text)
                            match_count = content.lower().count(query.lower())
                            warning(f"    {raw_url} ({size}b, {match_count} match(es))")
                            all_results["pastebin"].append({
                                "url": raw_url, "paste_id": pid, "size": size, "matches": match_count,
                                "preview": content[:200],
                            })
                        except requests.exceptions.RequestException:
                            pass
                else:
                    info("  No pastes found on Pastebin")
            elif resp.status_code == 403:
                info("  Pastebin returned HTTP 403 (Forbidden) - may be rate-limited or blocked")
            else:
                info(f"  Pastebin returned HTTP {resp.status_code}")
        except requests.exceptions.RequestException as e:
            info(f"  Pastebin search failed: {str(e)[:50]}")

        section(f"Phase 2: PSBDMP (Pastebin Dump) API Search")
        for psbdmp_url in [f"https://psbdmp.ws/api/search/{quote(query)}", f"https://psbdmp.ws/api/v3/search/{quote(query)}"]:
            try:
                resp = requests.get(
                    psbdmp_url, timeout=timeout,
                    headers=HEADERS, verify=False,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and data.get("count", 0) > 0:
                        count = data["count"]
                        warning(f"  Found {count} paste(s) via PSBDMP ({psbdmp_url})!")
                        all_results["psbdmp"] = data
                        for paste in data.get("data", [])[:10]:
                            pid = paste.get("id", "?")
                            title = paste.get("title", "untitled")[:50]
                            size = paste.get("size", 0)
                            warning(f"    ID: {pid} | {title} ({size}b)")
                        break
                    else:
                        info("  No results from PSBDMP")
                elif resp.status_code == 403:
                    info(f"  PSBDMP returned HTTP 403 for {psbdmp_url} - may be blocked")
                else:
                    info(f"  PSBDMP returned HTTP {resp.status_code} for {psbdmp_url}")
            except requests.exceptions.RequestException as e:
                info(f"  PSBDMP search failed for {psbdmp_url}: {str(e)[:50]}")
            except (ValueError, KeyError):
                info(f"  PSBDMP returned invalid data for {psbdmp_url}")

        section("Phase 3: Google Dorking for Paste Sites")
        dork_urls = [
            f"https://www.google.com/search?q=site:pastebin.com+{quote(query)}",
            f"https://www.google.com/search?q=site:rentry.co+{quote(query)}",
            f"https://www.google.com/search?q=site:paste.ee+{quote(query)}",
            f"https://www.google.com/search?q=site:hastebin.com+{quote(query)}",
            f"https://www.google.com/search?q=site:ghostbin.com+{quote(query)}",
            f"https://www.google.com/search?q=site:controlc.com+{quote(query)}",
            f"https://www.google.com/search?q=%22{quote(query)}%22+paste+OR+leak+OR+exposed+OR+dump",
            f"https://www.bing.com/search?q=%22{quote(query)}%22+paste+OR+leak+OR+exposed+OR+dump",
        ]
        for search_url in dork_urls:
            try:
                resp = requests.get(
                    search_url, timeout=timeout,
                    headers=HEADERS, verify=False,
                )
                if query.lower() in resp.text.lower():
                    match = re.search(r'href="(https?://[^"]+)"', resp.text[resp.text.find(query[:10]):])
                    if match:
                        info(f"  Mention found: {match.group(1)[:80]}")
                        all_results["mentions"].append({"url": match.group(1), "source": search_url[:50]})
            except requests.exceptions.RequestException:
                pass

        section("Phase 4: Recent Paste Monitoring")
        try:
            resp = requests.get(
                "https://pastebin.com/archive", timeout=timeout,
                headers=HEADERS, verify=False,
            )
            if resp.status_code == 200:
                recent_ids = re.findall(r'/raw/([a-zA-Z0-9]{8})', resp.text)
                recent_ids = list(set(recent_ids))[:20]
                info(f"Monitoring {len(recent_ids)} recent pastes for '{query}'...")
                matched = 0
                for pid in recent_ids:
                    try:
                        raw_url = f"https://pastebin.com/raw/{pid}"
                        raw_resp = requests.get(
                            raw_url, timeout=timeout,
                            headers=HEADERS, verify=False,
                        )
                        if query.lower() in raw_resp.text.lower():
                            warning(f"  MATCH in recent paste: {raw_url}")
                            all_results["recent"].append({
                                "url": raw_url, "paste_id": pid, "size": len(raw_resp.text),
                                "preview": raw_resp.text[:300],
                            })
                            matched += 1
                    except requests.exceptions.RequestException:
                        pass
                if matched == 0:
                    info("  No matches in recent pastes")
            elif resp.status_code == 403:
                info("  Archive returned HTTP 403 - may be rate-limited")
            else:
                info(f"  Archive returned HTTP {resp.status_code}")
        except requests.exceptions.RequestException as e:
            info(f"  Recent paste monitoring: {str(e)[:50]}")

        section("Paste Search Results Summary")
        total_pastebin = len(all_results["pastebin"])
        total_psbdmp = len(all_results.get("psbdmp", {}).get("data", [])) if isinstance(all_results.get("psbdmp"), dict) else 0
        total_recent = len(all_results["recent"])
        total_mentions = len(all_results["mentions"])

        if total_pastebin > 0 or total_psbdmp > 0 or total_recent > 0:
            error(f"  {query} found in public paste(s)!")
            result("Pastebin results", str(total_pastebin))
            result("PSBDMP results", str(total_psbdmp))
            result("Recent paste matches", str(total_recent))
            result("Search engine mentions", str(total_mentions))

            section("Matched Content Preview")
            for p in all_results["pastebin"] + all_results["recent"]:
                warning(f"  {p['url']}")
                result("    Match count", str(p.get("matches", "?")))
                result("    Size", f"{p['size']} bytes")
                preview = p.get("preview", "")
                if len(preview) > 200:
                    preview = preview[:200] + "..."
                info(f"    Preview: {preview}")
        else:
            success(f"  No public paste mentions found for '{query}'")
            info("  This does NOT guarantee safety — pastes can be private or unindexed")

        return all_results
