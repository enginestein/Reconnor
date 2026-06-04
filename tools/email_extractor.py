import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
BLACKLIST_DOMAINS = {"example.com", "domain.com", "yourdomain.com", "email.com", "mail.com", "test.com"}


def extract_from_url(url, timeout=10):
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True,
        )
        if resp.status_code == 200:
            emails = set(EMAIL_REGEX.findall(resp.text))
            filtered = {
                e for e in emails
                if not any(e.endswith(f".{ext}") for ext in ["png", "jpg", "gif", "svg", "css", "js"])
                and e.split("@")[1] not in BLACKLIST_DOMAINS
                if len(e.split("@")[0]) > 1
            }
            return url, filtered, resp.text
    except Exception:
        pass
    return url, set(), ""


class EmailExtractor:
    name = "email"
    description = "Extract email addresses from web pages"

    @staticmethod
    def run(target, crawl=False, depth=1, max=20):
        section(f"Email Extractor: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        all_emails = {}
        pages_checked = []

        if crawl:
            info(f"Crawling {target} (depth={depth}, max={max} pages)...")
            todo = {target}
            visited = set()
            for _ in range(depth):
                futures = {}
                next_todo = set()
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for url in todo:
                        if url in visited or len(visited) >= max:
                            visited.add(url)
                            continue
                        visited.add(url)
                        futures[executor.submit(extract_from_url, url)] = url
                    for future in as_completed(futures):
                        url, emails, html = future.result()
                        if emails:
                            pages_checked.append((url, emails))
                            for e in emails:
                                all_emails[e] = all_emails.get(e, 0) + 1
                        if html:
                            import bs4
                            soup = bs4.BeautifulSoup(html, "html.parser")
                            for a in soup.find_all("a", href=True):
                                link = urljoin(url, a["href"])
                                if urlparse(link).netloc == urlparse(target).netloc:
                                    next_todo.add(link)
                todo = next_todo - visited
                if len(visited) >= max:
                    break
            info(f"Checked {len(visited)} page(s)")
        else:
            url, emails, _ = extract_from_url(target)
            if emails:
                pages_checked.append((url, emails))
                for e in emails:
                    all_emails[e] = 1
            info("Checked single page (use --crawl for deeper scanning)")

        if all_emails:
            success(f"Found {len(all_emails)} unique email address(es):")
            for email, count in sorted(all_emails.items()):
                result(f"[{count}x]", email)
        else:
            warning("No email addresses found")

        return {"target": target, "emails": list(all_emails.keys()), "pages": len(pages_checked)}
