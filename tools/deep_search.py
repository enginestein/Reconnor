import re
import requests
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table

SEARCH_ENGINES = [
    ("Google", "https://www.google.com/search?q={query}"),
    ("Bing", "https://www.bing.com/search?q={query}"),
    ("Yandex", "https://yandex.com/search/?text={query}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={query}"),
    ("SearX", "https://searx.be/search?q={query}"),
    ("Qwant", "https://www.qwant.com/?q={query}"),
    ("Startpage", "https://www.startpage.com/do/dsearch?query={query}"),
    ("Mojeek", "https://www.mojeek.com/search?q={query}"),
    ("Brave", "https://search.brave.com/search?q={query}"),
    ("Swisscows", "https://swisscows.com/web?query={query}"),
]

SPECIALIZED_SEARCHES = {
    "Code & Repos": [
        ("GitHub", "https://github.com/search?q={query}&type=code"),
        ("GitLab", "https://gitlab.com/search?search={query}"),
        ("BitBucket", "https://bitbucket.org/search?query={query}"),
        ("SourceForge", "https://sourceforge.net/directory/?q={query}"),
        ("CodeBerg", "https://codeberg.org/explore/repos?q={query}"),
        ("NPM", "https://www.npmjs.com/search?q={query}"),
        ("PyPI", "https://pypi.org/search/?q={query}"),
    ],
    "Documents & Files": [
        ("Scribd", "https://www.scribd.com/search?q={query}"),
        ("SlideShare", "https://www.slideshare.net/search/search?q={query}"),
        ("Issuu", "https://issuu.com/search?q={query}"),
        ("Google Drive", "https://drive.google.com/drive/search?q={query}"),
        ("pdf", "https://www.google.com/search?q={query}+filetype:pdf"),
        ("docx", "https://www.google.com/search?q={query}+filetype:docx"),
        ("xlsx", "https://www.google.com/search?q={query}+filetype:xlsx"),
    ],
    "News & Media": [
        ("Google News", "https://news.google.com/search?q={query}"),
        ("Reddit", "https://www.reddit.com/search/?q={query}"),
        ("Hacker News", "https://hn.algolia.com/?query={query}"),
        ("Medium", "https://medium.com/search?q={query}"),
        ("Dev.to", "https://dev.to/search?q={query}"),
        ("Wikipedia", "https://en.wikipedia.org/wiki/Special:Search?search={query}"),
    ],
    "People & Social": [
        ("Facebook", "https://www.facebook.com/search/top/?q={query}"),
        ("LinkedIn", "https://www.linkedin.com/search/results/all/?keywords={query}"),
        ("Twitter", "https://twitter.com/search?q={query}"),
        ("Instagram", "https://www.instagram.com/web/search/topsearch/?query={query}"),
        ("YouTube", "https://www.youtube.com/results?search_query={query}"),
        ("TikTok", "https://www.tiktok.com/search?q={query}"),
    ],
    "Public Records": [
        ("Archive.org", "https://archive.org/search.php?query={query}"),
        ("OpenCorporates", "https://opencorporates.com/search?q={query}"),
        ("Crunchbase", "https://www.crunchbase.com/search/organizations/field/organizations/{query}"),
        ("Glassdoor", "https://www.glassdoor.com/Search/results.htm?keyword={query}"),
        ("GovInfo", "https://www.govinfo.gov/search?query={query}"),
    ],
    "Security Research": [
        ("Exploit DB", "https://www.exploit-db.com/search?q={query}"),
        ("CVE Details", "https://www.cvedetails.com/search.php?q={query}"),
        ("NVD", "https://nvd.nist.gov/vuln/search/results?query={query}"),
        ("Shodan", "https://www.shodan.io/search?query={query}"),
        ("Censys", "https://search.censys.io/search?resource=hosts&q={query}"),
        ("VirusTotal", "https://www.virustotal.com/gui/search/{query}"),
        ("HaveIBeenPwned", "https://haveibeenpwned.com/account/{query}"),
        ("URLScan", "https://urlscan.io/search/#{query}"),
        ("AlienVault OTX", "https://otx.alienvault.com/browse/global/pulses/?q={query}"),
    ],
}

FILE_TYPES = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "json", "xml", "csv", "sql", "db", "backup", "log", "conf", "cfg",
    "env", "yml", "yaml", "ini", "bat", "sh", "ps1", "exe", "dll",
    "zip", "rar", "tar", "gz", "7z", "iso", "img", "dmg",
]

DORK_OPERATORS = [
    "site", "filetype", "intitle", "inurl", "intext", "allinurl",
    "allintitle", "allintext", "ext", "link", "related", "cache",
    "stie", "before", "after", "daterange", "numrange",
]


class DeepSearch:
    name = "deep-search"
    description = "Deep internet search engine: cross-engine search, file types, code repositories, people search, security research, and Google dorking"

    @staticmethod
    def run(target, timeout=10, limit=20):
        section(f"Deep Internet Search: {target}")

        query = target.strip()
        if not query:
            error("No search query provided")
            return {"query": query, "error": "No query"}

        results = {"general": [], "specialized": {}, "file_types": [], "dork_suggestions": []}

        section("Phase 1: Cross-Engine Search")
        info(f"Searching {len(SEARCH_ENGINES)} search engines for '{query}'...")
        for engine_name, search_url in SEARCH_ENGINES:
            try:
                url = search_url.format(query=quote(query))
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                result_urls = re.findall(r'https?://[a-zA-Z0-9./?=%-_]+', resp.text)
                total_urls = len([u for u in result_urls if u.startswith("http") and not any(s in u for s in ["google", "bing.com/search?", "yandex", "searx"])])
                info(f"  [{engine_name}] {resp.status_code} - {total_urls} URLs found")
                results["general"].append({"engine": engine_name, "status": resp.status_code, "urls_found": total_urls})
            except Exception as e:
                info(f"  [{engine_name}] Error: {str(e)[:50]}")

        section("Phase 2: Specialized Search Engines")
        for category, engines in SPECIALIZED_SEARCHES.items():
            info(f"Searching {category}...")
            category_results = []
            for engine_name, search_url in engines:
                try:
                    url = search_url.format(query=quote(query))
                    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    if resp.status_code == 200:
                        info(f"  [{engine_name}] {resp.status_code}")
                        category_results.append({"engine": engine_name, "url": url, "status": resp.status_code, "found": True})
                    else:
                        info(f"  [{engine_name}] HTTP {resp.status_code}")
                        category_results.append({"engine": engine_name, "url": url, "status": resp.status_code, "found": False})
                except:
                    info(f"  [{engine_name}] Connection failed")
                    category_results.append({"engine": engine_name, "url": "", "status": 0, "found": False})
            results["specialized"][category] = category_results

        section("Phase 3: File Type Discovery")
        info(f"Checking common file types for '{query}'...")
        for file_type in FILE_TYPES[:10]:
            try:
                url = f"https://www.google.com/search?q={quote(query)}+filetype:{file_type}"
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                result_links = re.findall(r'href="(https?://[^"]+\.' + file_type + r'[^"]*)"', resp.text)
                result_links = list(set(result_links))
                if result_links:
                    info(f"  .{file_type}: {len(result_links)} result(s)")
                    for link in result_links[:3]:
                        info(f"    {link[:80]}")
                    results["file_types"].append({"type": file_type, "urls": result_links[:5], "count": len(result_links)})
                else:
                    info(f"  .{file_type}: 0 results")
            except:
                pass

        section("Phase 4: Google Dork Suggestions")
        info(f"Generating dork queries for '{query}'...")
        dork_suggestions = [
            f"site:{query}",
            f"site:*.{query}",
            f"intitle:\"{query}\"",
            f"inurl:{query}",
            f"intext:\"{query}\"",
            f"filetype:pdf \"{query}\"",
            f"filetype:txt \"{query}\"",
            f"filetype:sql \"{query}\"",
            f"filetype:env \"{query}\"",
            f"filetype:conf \"{query}\"",
            f"filetype:log \"{query}\"",
            f"filetype:csv \"{query}\"",
            f"filetype:json \"{query}\"",
            f"filetype:bak \"{query}\"",
            f"filetype:backup \"{query}\"",
            f"ext:php intitle:phpinfo \"{query}\"",
            f"ext:xml \"{query}\"",
            f"ext:yml \"{query}\"",
            f"ext:yaml \"{query}\"",
            f"ext:ini \"{query}\"",
            f"inurl:admin \"{query}\"",
            f"inurl:dashboard \"{query}\"",
            f"inurl:config \"{query}\"",
            f"inurl:backup \"{query}\"",
            f"inurl:wp-admin \"{query}\"",
            f"intitle:\"index of\" \"{query}\"",
            f"intitle:\"Index of /\" \"{query}\"",
            f"-\"thanks\" -\"error\" \"{query}\"",
            f"site:pastebin.com \"{query}\"",
            f"site:github.com \"{query}\"",
            f"site:gitlab.com \"{query}\"",
            f"site:linkedin.com \"{query}\"",
            f"site:facebook.com \"{query}\"",
            f"site:instagram.com \"{query}\"",
            f"site:reddit.com \"{query}\"",
            f"site:stackoverflow.com \"{query}\"",
            f"site:s3.amazonaws.com \"{query}\"",
            f"site:blob.core.windows.net \"{query}\"",
            f"site:storage.googleapis.com \"{query}\"",
        ]
        info(f"Generated {len(dork_suggestions)} dork suggestions")
        results["dork_suggestions"] = dork_suggestions

        section("Phase 5: Wayback Machine Historical Search")
        try:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url={quote(query)}&output=text&limit=10"
            resp = requests.get(wayback_url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200 and len(resp.text) > 50:
                snapshot_count = len(resp.text.strip().split("\n"))
                info(f"  Wayback Machine: {snapshot_count} snapshots archived")
        except:
            pass

        section("Deep Search Results Summary")
        total_general = len(results["general"])
        total_specialized = sum(len(v) for k, v in results["specialized"].items())
        total_file_types = len(results["file_types"])
        total_dorks = len(results["dork_suggestions"])

        result("Query", query)
        result("Engines searched", str(total_general))
        result("Specialized searches", str(total_specialized))
        result("File types with results", str(total_file_types))
        result("Dork suggestions", str(total_dorks))

        successful_engines = [r["engine"] for r in results["general"] if r.get("urls_found", 0) > 0]
        if successful_engines:
            success(f"Engines with results: {', '.join(successful_engines[:5])}")

        for category, cat_results in results["specialized"].items():
            found = [r for r in cat_results if r.get("found")]
            if found:
                engines_str = ", ".join(r["engine"] for r in found[:3])
                info(f"  {category}: {len(found)} accessible — {engines_str}")

        if results["file_types"]:
            section("File Type Matches")
            file_table = [[ft["type"], str(ft["count"]), (ft["urls"][0][:50] if ft["urls"] else "")] for ft in results["file_types"][:5]]
            table(["Type", "Count", "Example URL"], file_table)

        if results["dork_suggestions"]:
            section("Top Dork Queries")
            for dork in results["dork_suggestions"][:10]:
                info(f"  {dork}")
            if len(results["dork_suggestions"]) > 10:
                info(f"  ... and {len(results['dork_suggestions']) - 10} more (total: {len(results['dork_suggestions'])})")

        return results
