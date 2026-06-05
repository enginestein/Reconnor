import requests
from urllib.parse import urljoin, urlparse
from collections import deque

from utils.output import section, info, success, warning, error, result, table
from utils.external_tools import gospider_crawl, hakrawler_crawl, find_tool

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


def get_page_links(url, base_domain, timeout=10):
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            allow_redirects=True,
        )
        if resp.status_code != 200:
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
        return links, 200
    except Exception as e:
        return [], str(e)


class WebCrawler:
    name = "crawl"
    description = "Crawl a website to enumerate URLs and structure"

    @staticmethod
    def run(target, depth=2, max_urls=100, timeout=10, ext=False):
        section(f"Web Crawler: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        if ext:
            section("External Crawling Tools")
            all_urls = set()

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

        while to_visit and len(visited) < max_urls:
            current_url, current_depth = to_visit.popleft()

            if current_url in visited:
                continue
            if current_depth > depth:
                continue

            visited.add(current_url)
            current_depth_str = current_depth

            links, status = get_page_links(current_url, base_domain, timeout)
            url_tree[current_url] = {"depth": current_depth, "status": status, "links": len(links)}

            if isinstance(status, int) and status == 200 and current_depth < depth:
                for link in links:
                    if link not in visited:
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
        result("Max depth reached", str(max(data["depth"] for data in url_tree.values())))
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
