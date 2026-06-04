import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table


def get_links(url, timeout=10):
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        if resp.status_code != 200:
            return url, [], resp.status_code

        import bs4
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "source", "form"], href=True):
            href = tag.get("href") or tag.get("src") or ""
            full_url = urljoin(url, href)
            links.append(full_url)
        return url, links, 200
    except Exception as e:
        return url, [], str(e)


def check_link(url, timeout=5):
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        return url, resp.status_code
    except:
        return url, "Error"


class LinkExtractor:
    name = "links"
    description = "Extract and analyze links from a web page"

    @staticmethod
    def run(target, check=False, threads=20):
        section(f"Link Extractor: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_domain = parsed.netloc

        url, links, status = get_links(target)

        if status != 200:
            error(f"Failed to fetch page: HTTP {status}")
            return {"target": target, "error": f"HTTP {status}"}

        internal = []
        external = []
        resources = []

        for link in set(links):
            link_parsed = urlparse(link)
            if not link_parsed.netloc:
                internal.append(link)
            elif base_domain in link_parsed.netloc:
                internal.append(link)
            else:
                external.append(link)

            ext = link.rsplit(".", 1)[-1].lower() if "." in link else ""
            if ext in ["css", "js", "png", "jpg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot"]:
                resources.append(link)

        info(f"Found {len(internal)} internal, {len(external)} external, {len(resources)} resource link(s)")

        section("Internal Links")
        for link in sorted(internal)[:30]:
            print(f"  {link}")
        if len(internal) > 30:
            info(f"... and {len(internal) - 30} more")

        section("External Links (sample)")
        for link in sorted(external)[:15]:
            print(f"  {link}")

        section("Resource Files")
        for link in sorted(resources)[:20]:
            print(f"  {link}")

        if check and (internal or external):
            section("Link Health Check")
            all_links = internal[:30] + external[:10]
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(check_link, link): link for link in all_links}
                broken = []
                for future in as_completed(futures):
                    link, code = future.result()
                    if code == 404:
                        warning(f"BROKEN (404): {link}")
                        broken.append((link, code))
                    elif code == 403:
                        info(f"FORBIDDEN (403): {link}")
                    elif code == "Error":
                        info(f"ERROR: {link}")

            if broken:
                warning(f"Found {len(broken)} broken link(s)")
            else:
                success("No broken links found in sample")

        return {"target": target, "internal": len(internal), "external": len(external), "resources": len(resources)}
