import time
import random
import requests
from datetime import datetime
from urllib.parse import urlparse

from utils.output import section, info, success, warning, error, result, table


CDX_API = "https://web.archive.org/cdx/search/cdx"

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def fetch_wayback_urls(target, limit=500):
    params = {
        "url": f"{target}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,length",
        "limit": limit,
        "collapse": "urlkey",
    }
    last_error = None
    for attempt in range(3):
        user_agent = random.choice(USER_AGENTS)
        headers = {"User-Agent": user_agent}
        try:
            resp = requests.get(CDX_API, params=params, timeout=60, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data[1:] if len(data) > 1 else []
            else:
                last_error = f"Wayback API returned status {resp.status_code}"
                error(last_error)
        except requests.exceptions.Timeout:
            last_error = f"Wayback API timeout (attempt {attempt + 1}/3)"
            warning(last_error)
        except requests.exceptions.RequestException as e:
            last_error = f"Wayback API request failed: {e}"
            warning(last_error)
        except (ValueError, IndexError):
            last_error = "Wayback API returned invalid JSON"
            warning(last_error)

        if attempt < 2:
            backoff = (2 ** attempt) + random.uniform(0, 1)
            info(f"  Retrying in {backoff:.1f}s...")
            time.sleep(backoff)

    error(last_error or "Wayback API request failed after 3 attempts")
    return []


class WaybackScraper:
    name = "wayback"
    description = "Fetch historical URLs from Wayback Machine"

    @staticmethod
    def run(target, limit=500, all=False):
        unique = not all
        section(f"Wayback Machine Scraper: {target}")

        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.netloc or target

        info(f"Fetching up to {limit} historical URLs for {target}...")
        results = fetch_wayback_urls(target, limit)

        if not results:
            warning("No historical URLs found")
            return {"target": target, "urls": []}

        if unique:
            unique_urls = {}
            for entry in results:
                if len(entry) >= 3:
                    ts, url, status = entry[0], entry[1], entry[2] if len(entry) > 2 else "200"
                    if url not in unique_urls:
                        unique_urls[url] = (ts, status)
            deduped = [(ts, url, status) for url, (ts, status) in unique_urls.items()]
            info(f"Found {len(results)} total snapshots, {len(deduped)} unique URLs")
            results = deduped
        else:
            results = [(e[0], e[1], e[2] if len(e) > 2 else "-") for e in results]
            info(f"Found {len(results)} snapshots")

        status_count = {}
        for ts, url, status in results:
            status_count[status] = status_count.get(status, 0) + 1

        section("Status Code Distribution")
        for code, count in sorted(status_count.items()):
            result(f"HTTP {code}", str(count))

        section("Historical URLs (sample)")
        display = results[:50]
        table(
            ["TIMESTAMP", "STATUS", "URL"],
            [(ts[:14], status, url[:80]) for ts, url, status in display]
        )

        if len(results) > 50:
            info(f"... and {len(results) - 50} more URLs (showing first 50)")

        file_types = {}
        for _, url, _ in results:
            ext = url.rsplit(".", 1)[-1] if "." in url else "none"
            file_types[ext] = file_types.get(ext, 0) + 1

        section("File Type Distribution")
        for ext, count in sorted(file_types.items(), key=lambda x: -x[1])[:15]:
            result(f".{ext}", str(count))

        info(f"Wayback scrape complete: {len(results)} snapshots found")
        return {"target": target, "total": len(results), "urls": results}
