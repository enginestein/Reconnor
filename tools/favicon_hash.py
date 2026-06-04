import requests
import struct
from utils.output import section, info, success, warning, error, result

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

def mmh3_hash_32(data):
    if HAS_MMH3:
        return mmh3.hash(data)
    h = 0
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        h ^= struct.unpack('<I', chunk)[0]
        h = (h * 0x5bd1e995) & 0xFFFFFFFF
    return h

def fetch_favicon(target):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    urls_to_try = [
        f"{target.rstrip('/')}/favicon.ico",
    ]

    parsed = requests.utils.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    urls_to_try.append(f"{base}/favicon.ico")

    if parsed.path and parsed.path != "/":
        dir_path = base + parsed.path.rsplit("/", 1)[0] + "/favicon.ico"
        urls_to_try.append(dir_path)

    for url in urls_to_try:
        try:
            resp = requests.get(url, timeout=15,
                                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and len(resp.content) > 10:
                return resp.content, url
        except Exception:
            continue

    try:
        resp = requests.get(base, timeout=15,
                            headers={"User-Agent": "Mozilla/5.0"})
        html = resp.text
        import re
        favicon_match = re.search(
            r'<link[^>]+rel=["\']?(?:shortcut )?icon["\']?[^>]+href=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if not favicon_match:
            favicon_match = re.search(
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']?(?:shortcut )?icon["\']?',
                html, re.IGNORECASE
            )
        if favicon_match:
            href = favicon_match.group(1)
            if href.startswith("//"):
                href = parsed.scheme + ":" + href
            elif href.startswith("/"):
                href = base + href
            elif not href.startswith("http"):
                href = base.rstrip("/") + "/" + href.lstrip("/")
            resp2 = requests.get(href, timeout=15,
                                 headers={"User-Agent": "Mozilla/5.0"})
            if resp2.status_code == 200 and len(resp2.content) > 10:
                return resp2.content, href
    except Exception:
        pass

    return None, None

class FaviconHash:
    name = "favicon"
    description = "Calculate favicon hash (mmh3) for Shodan/device identification"

    @staticmethod
    def run(target):
        section(f"Favicon Hash Calculator: {target}")

        data, source_url = fetch_favicon(target)
        if not data:
            error("Could not retrieve favicon")
            return {"target": target, "error": "No favicon found"}

        info(f"Favicon URL: {source_url}")
        info(f"Favicon size: {len(data)} bytes")

        h = mmh3_hash_32(data)
        hash_value = h if h <= 0x7FFFFFFF else h - 0x100000000

        result("mmh3 hash", str(hash_value))
        result("Shodan query", f"http.favicon.hash:{hash_value}")

        success(f"Favicon hash: {hash_value}")
        info(f"Use this in Shodan: http.favicon.hash:{hash_value}")

        if not HAS_MMH3:
            warning("Install mmh3 for accurate Shodan-compatible hashing: pip install mmh3")

        return {"target": target, "hash": hash_value, "url": source_url}
