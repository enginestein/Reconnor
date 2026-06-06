import re
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table
from utils.external_tools import gospider_crawl, hakrawler_crawl, find_tool

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def parse_sitemap(sitemap_url, timeout=10):
    try:
        resp = requests.get(
            sitemap_url, timeout=timeout, headers=HEADERS, allow_redirects=True,
        )
        if resp.status_code != 200:
            return []
        root = ET.fromstring(resp.content)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = [loc.text for loc in root.findall(".//sm:loc", ns) if loc.text]
        return urls
    except Exception:
        return []


def parse_robots(robots_url, base_url, timeout=10):
    disallowed = []
    sitemaps = []
    try:
        resp = requests.get(
            robots_url, timeout=timeout, headers=HEADERS, allow_redirects=True,
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                m = re.match(r"Disallow:\s*(.*)", line, re.I)
                if m:
                    disallowed.append(m.group(1).strip())
                m = re.match(r"Sitemap:\s*(.*)", line, re.I)
                if m:
                    sitemaps.append(m.group(1).strip())
    except Exception:
        pass
    return disallowed, sitemaps


def is_allowed(url, disallowed_patterns):
    parsed = urlparse(url)
    path = parsed.path
    for pattern in disallowed_patterns:
        if pattern and path.startswith(pattern):
            return False
    return True


def extract_js_urls(html, base_url):
    js_urls = set()
    script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.I)
    for m in script_pattern.finditer(html):
        js_urls.add(urljoin(base_url, m.group(1)))
    inline_pattern = re.compile(
        r'(?:location\.href|window\.location|document\.URL)\s*[=+]\s*["\']([^"\']+)["\']', re.I,
    )
    for m in inline_pattern.finditer(html):
        js_urls.add(urljoin(base_url, m.group(1)))
    fetch_pattern = re.compile(
        r'(?:fetch|axios\.get|ajax)\s*\(\s*["\']([^"\']+)["\']', re.I,
    )
    for m in fetch_pattern.finditer(html):
        js_urls.add(urljoin(base_url, m.group(1)))
    return list(js_urls)


def get_page_links(url, base_domain, timeout=10):
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers=HEADERS,
            allow_redirects=True,
        )
        if resp.status_code not in [200, 301, 302, 307, 308]:
            return [], resp.status_code

        if not HAS_BS4:
            return [], 200

        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            if base_domain in parsed.netloc or not parsed.netloc:
                fragment_removed = full_url.split("#")[0]
                if fragment_removed and fragment_removed not in links:
                    links.append(fragment_removed)

        js_urls = extract_js_urls(resp.text, url)
        for js_url in js_urls:
            parsed = urlparse(js_url)
            if base_domain in parsed.netloc or not parsed.netloc:
                if js_url not in links:
                    links.append(js_url)

        return links, 200
    except Exception as e:
        return [], str(e)


class WebCrawler:
    name = "crawl"
    description = "Crawl a website to enumerate URLs and structure"

    @staticmethod
    def run(target, depth=2, max_urls=500, timeout=10, ext=False):
        section(f"Web Crawler: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        crawl_urls = set()

        robots_url = urljoin(target, "/robots.txt")
        info(f"Fetching {robots_url}...")
        disallowed, sitemaps = parse_robots(robots_url, target, timeout)
        if disallowed:
            info(f"  Found {len(disallowed)} Disallow rule(s) in robots.txt")
        for sm_url in sitemaps:
            info(f"  Found sitemap in robots.txt: {sm_url}")
            sitemap_urls = parse_sitemap(sm_url, timeout)
            if sitemap_urls:
                info(f"  Sitemap yielded {len(sitemap_urls)} URLs")
                for u in sitemap_urls:
                    crawl_urls.add(u)

        sitemap_url = urljoin(target, "/sitemap.xml")
        sitemap_urls = parse_sitemap(sitemap_url, timeout)
        if sitemap_urls:
            info(f"/sitemap.xml yielded {len(sitemap_urls)} URLs")
            for u in sitemap_urls:
                crawl_urls.add(u)

        if ext:
            section("External Crawling Tools")
            all_urls = set(crawl_urls)

            gs = gospider_crawl(target, depth)
            if gs:
                for url in gs:
                    all_urls.add(url)
                success(f"gospider found {len(gs)} URLs")

            hk = hakrawler_crawl(target, depth)
            if hk:
                for url in hk:
                    all_urls.add(url)
                success(f"hakrawler found {len(hk)} URLs")

            if all_urls:
                section(f"Discovered URLs ({len(all_urls)})")
                for url in sorted(all_urls)[:200]:
                    info(f"  {url}")
                if len(all_urls) > 200:
                    info(f"... and {len(all_urls) - 200} more URLs")
                return {"target": target, "urls": sorted(all_urls)}

        if not HAS_BS4:
            warning("beautifulsoup4 not installed. Install with: pip install beautifulsoup4")

        parsed = urlparse(target)
        base_domain = parsed.netloc

        info(f"Crawling {target} (max depth={depth}, max URLs={max_urls})...")

        visited = set()
        to_visit = deque([(target, 0)])
        url_tree = {}
        errors = 0

        def fetch_page(url_data):
            url, current_depth = url_data
            if url in visited:
                return None
            if current_depth > depth:
                return None
            links, status = get_page_links(url, base_domain, timeout)
            return url, current_depth, links, status

        with ThreadPoolExecutor(max_workers=10) as executor:
            while to_visit and len(visited) < max_urls:
                batch = []
                while to_visit and len(batch) < 10:
                    batch.append(to_visit.popleft())

                futures = [executor.submit(fetch_page, item) for item in batch]

                for future in as_completed(futures):
                    result_data = future.result()
                    if result_data is None:
                        continue
                    url, current_depth, links, status = result_data

                    if url in visited:
                        continue
                    if not is_allowed(url, disallowed) and url != target:
                        continue

                    visited.add(url)
                    url_tree[url] = {"depth": current_depth, "status": status, "links": len(links)}

                    if isinstance(status, int) and status in [200, 301, 302, 307, 308] and current_depth < depth:
                        for link in links:
                            if link not in visited and link not in [item[0] for item in to_visit]:
                                to_visit.append((link, current_depth + 1))

                    if len(visited) % 20 == 0:
                        info(f"Crawled {len(visited)} URLs...")

        info(f"Crawl complete: {len(visited)} URLs visited")

        total_links = sum(data["links"] for data in url_tree.values())

        by_depth = {}
        for url, data in url_tree.items():
            d = data["depth"]
            by_depth[d] = by_depth.get(d, 0) + 1

        section("Crawl Summary")
        result("Total URLs", str(len(visited)))
        result("Total links found", str(total_links))
        result("Max depth reached", str(max(data["depth"] for data in url_tree.values())) if url_tree else "0")
        for d in sorted(by_depth.keys()):
            result(f"  Depth {d}", f"{by_depth[d]} URLs")

        section("Discovered URLs")
        depth_order = sorted(url_tree.items(), key=lambda x: (x[1]["depth"], x[0]))
        for url, data in depth_order:
            indent = "  " * data["depth"]
            status_str = f"[{data['status']}]" if isinstance(data["status"], int) else "[ERR]"
            print(f"{indent}{status_str} {url} ({data['links']} links)")
            if len(url_tree) > max_urls:
                break

        section("URLs by Path Depth")
        path_depth = {}
        for url in url_tree:
            path = urlparse(url).path
            segments = [s for s in path.split("/") if s]
            d = len(segments)
            path_depth[d] = path_depth.get(d, 0) + 1

        for d in sorted(path_depth.keys()):
            result(f"  {d} segment(s)", f"{path_depth[d]} URLs")

        return {"target": target, "urls_visited": len(visited), "url_tree": url_tree}
