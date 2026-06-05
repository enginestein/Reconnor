import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper
from utils.external_tools import subjs_scan, linkfinder_scan

JS_URL_PATTERN = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
API_PATTERN = re.compile(r'(?:api|v1|v2|v3|rest|graphql|endpoint|webhook)/[a-zA-Z0-9_\-/]+', re.IGNORECASE)
ROUTE_PATTERN = re.compile(r'["\'](/\w+(?:/\w+)*)["\']')
SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|apikey|secret|token|auth|password|passwd|jwt|bearer)'
    r'[\s:="\']+([a-zA-Z0-9_\-\.]{16,64})',
    re.IGNORECASE
)
ENDPOINT_PATTERN = re.compile(r'["\'](/(?:api|rest|graphql|v1|v2|v3|service|ws|webhook|endpoint|rpc)/[^"\']*)["\']', re.IGNORECASE)


def fetch_js_file(url, timeout=15):
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            allow_redirects=True,
        )
        if resp.status_code == 200:
            return url, resp.text
        return url, None
    except:
        return url, None


class JSScraper:
    name = "js"
    description = "Extract API endpoints, secrets, and routes from JavaScript files"

    @staticmethod
    def run(target, threads=20, ollama_model=None, ext=False):
        section(f"JavaScript Scraper: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        ext_js_urls = set()
        ext_endpoints = set()

        if ext:
            section("External JS Discovery Tools")
            sj = subjs_scan(target)
            if sj:
                ext_js_urls.update(sj)
                success(f"subjs found {len(sj)} JS files")

            lf = linkfinder_scan(target)
            if lf:
                for ep in lf:
                    if ep.startswith("/"):
                        ext_endpoints.add(ep)
                    elif ep.startswith("http"):
                        ext_js_urls.add(ep)
                success(f"linkfinder found {len(lf)} endpoints/files")

        try:
            resp = requests.get(
                target, timeout=15,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
            )
            html = resp.text
            base_url = resp.url
        except Exception as e:
            error(f"Failed to fetch page: {e}")
            return {"target": target, "error": str(e)}

        js_urls = list(ext_js_urls)
        for match in JS_URL_PATTERN.finditer(html):
            js_path = match.group(1)
            full_url = urljoin(base_url, js_path)
            if full_url not in js_urls:
                js_urls.append(full_url)

        inline_js = []
        inline_pattern = re.compile(r'<script[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
        for match in inline_pattern.finditer(html):
            code = match.group(1).strip()
            if code and len(code) > 50:
                inline_js.append(code)

        info(f"Found {len(js_urls)} external JS file(s), {len(inline_js)} inline script(s)")

        all_js_content = ""
        found_endpoints = set()
        found_secrets = set()
        found_routes = set()

        for js_code in inline_js:
            all_js_content += js_code + "\n"

        if js_urls:
            section("External JavaScript Files")
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(fetch_js_file, url): url for url in js_urls}
                for future in as_completed(futures):
                    url, content = future.result()
                    if content:
                        size_kb = len(content) / 1024
                        result(url.split("/")[-1], f"{size_kb:.1f} KB - {url}")
                        all_js_content += content + "\n"
                    else:
                        warning(f"Failed: {url}")

        if all_js_content:
            for match in ENDPOINT_PATTERN.finditer(all_js_content):
                endpoint = match.group(1)
                if len(endpoint) > 5:
                    found_endpoints.add(endpoint)

            for match in API_PATTERN.finditer(all_js_content):
                api_path = match.group(0)
                if len(api_path) > 8:
                    found_endpoints.add("/" + api_path)

            for match in SECRET_PATTERN.finditer(all_js_content):
                secret = match.group(0).strip()
                if len(secret) > 20:
                    found_secrets.add(secret[:80])

            for match in ROUTE_PATTERN.finditer(all_js_content):
                route = match.group(1)
                if route.count("/") <= 4 and len(route) > 3 and "." not in route.split("/")[-1]:
                    found_routes.add(route)

        if found_endpoints:
            section(f"API Endpoints ({len(found_endpoints)})")
            for ep in sorted(found_endpoints)[:50]:
                success(ep)
            if len(found_endpoints) > 50:
                info(f"... and {len(found_endpoints) - 50} more endpoints")

        if found_secrets:
            section(f"Potential Secrets/Tokens ({len(found_secrets)})")
            warning("SECURITY ISSUE: Possible hardcoded secrets found!")
            for secret in sorted(found_secrets)[:20]:
                warning(f"  {secret[:100]}")
            if len(found_secrets) > 20:
                info(f"... and {len(found_secrets) - 20} more potential secrets")

        if found_routes:
            section(f"Internal Routes ({len(found_routes)})")
            for route in sorted(found_routes)[:30]:
                info(f"  {route}")
            if len(found_routes) > 30:
                info(f"... and {len(found_routes) - 30} more routes")

        if ollama and ollama.available and all_js_content:
            section("Ollama: AI-Powered JS Analysis")
            ai_secrets = ollama.analyze_js_for_secrets(all_js_content, target)
            if ai_secrets:
                info(f"Ollama found {len(ai_secrets)} items:")
                for s in ai_secrets[:15]:
                    if s and len(s) > 5:
                        warning(f"  {s}")
                        found_secrets.add(s[:100])
            ai_endpoints = ollama.find_js_endpoints(all_js_content, target)
            if ai_endpoints:
                info(f"Ollama found {len(ai_endpoints)} additional endpoints:")
                for ep in ai_endpoints[:15]:
                    if ep and len(ep) > 5:
                        success(f"  {ep}")
                        found_endpoints.add(ep)

        all_endpoints = found_endpoints.union(ext_endpoints)
        if ext_endpoints:
            section(f"External Endpoints ({len(ext_endpoints)})")
            for ep in sorted(ext_endpoints)[:30]:
                success(ep)

        if not any([all_endpoints, found_secrets, found_routes]):
            warning("No endpoints, secrets, or routes found in JavaScript")

        return {
            "target": target,
            "js_files": len(js_urls),
            "endpoints": sorted(all_endpoints),
            "secrets": sorted(found_secrets)[:20],
            "routes": sorted(found_routes),
        }
