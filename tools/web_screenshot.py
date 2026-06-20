import os
import time
import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class WebScreenshot:
    name = "screenshot"
    description = "Take full-page screenshots of websites using Playwright"

    @staticmethod
    def run(target, output_dir="screenshots", width=1280, height=720, full_page=True, timeout=30, delay=0):
        section(f"Web Screenshot: {target}")

        results = {"target": target, "screenshot_path": None, "error": None}

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        domain = parsed.netloc or parsed.hostname or "unknown"
        domain = domain.replace(":", "_")

        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            info(f"Created output directory: {output_dir}")

        safe_name = domain.replace(".", "_").replace("/", "_").replace(":", "_")
        timestamp = f"_{int(time.time())}"
        filename = f"{safe_name}{timestamp}.png"
        filepath = os.path.join(output_dir, filename)

        if not HAS_PLAYWRIGHT:
            msg = "Playwright not installed. Install with: pip install playwright && playwright install chromium"
            error(msg)
            results["error"] = msg

            info("Falling back to HTTP status check...")
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                success(f"Website is reachable: {target} ({resp.status_code})")
                result("Status", str(resp.status_code))
                result("Content-Length", str(len(resp.content)))
                results["status_code"] = resp.status_code
                results["content_length"] = len(resp.content)
            except Exception as e:
                error(f"Cannot reach {target}: {e}")
                results["error"] = f"Cannot reach target: {e}"

            return results

        info(f"Taking screenshot of {target}...")
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                )
                page = context.new_page()

                wait_states = ["networkidle", "load", "domcontentloaded"]
                status = "unknown"
                for wait_until in wait_states:
                    try:
                        resp = page.goto(target, wait_until=wait_until, timeout=timeout * 1000)
                        status = resp.status if resp else "unknown"
                        break
                    except Exception as e:
                        info(f"wait_until={wait_until} failed: {e}")

                if delay:
                    page.wait_for_timeout(int(delay * 1000))

                scroll_height = page.evaluate("document.body.scrollHeight")
                for y in range(0, scroll_height, height):
                    page.evaluate(f"window.scrollTo(0, {y})")
                    page.wait_for_timeout(80)
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(300)

                page.screenshot(path=filepath, full_page=full_page)
                browser.close()

            file_size = os.path.getsize(filepath)
            success(f"Screenshot saved: {filepath} ({file_size / 1024:.1f} KB)")
            result("URL", target)
            result("Status", str(status))
            result("File", filepath)
            result("Size", f"{file_size / 1024:.1f} KB")
            result("Viewport", f"{width}x{height}")
            result("Full Page", str(full_page))

            results["screenshot_path"] = filepath
            results["status_code"] = status
            results["file_size"] = file_size

        except Exception as e:
            error(f"Screenshot failed: {e}")
            results["error"] = str(e)

        return results
