import socket
import requests
from utils.output import section, info, success, warning, error, result, table

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS) - forces HTTPS",
        "good": True,
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP) - mitigates XSS",
        "good": True,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "good": True,
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "good": True,
    },
    "X-XSS-Protection": {
        "description": "Cross-site scripting filter",
        "good": True,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "good": True,
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "good": True,
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS header - check if too permissive",
        "good": False,
    },
    "Server": {
        "description": "Server info disclosure",
        "good": False,
    },
    "X-Powered-By": {
        "description": "Technology info disclosure",
        "good": False,
    },
    "Set-Cookie": {
        "description": "Check for Secure/HttpOnly flags",
        "good": None,
    },
}

INFO_HEADERS = ["Server", "X-Powered-By", "Via", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeaderAnalyzer:
    name = "headers"
    description = "Analyze HTTP security headers"

    @staticmethod
    def run(target):
        section(f"HTTP Header Analysis: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            resp = requests.get(
                target,
                timeout=15,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0)"}
            )
        except requests.exceptions.SSLError:
            try:
                target_http = target.replace("https://", "http://")
                resp = requests.get(
                    target_http,
                    timeout=15,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
            except requests.exceptions.RequestException as e:
                error(f"Request failed: {e}")
                return {"target": target, "error": str(e)}
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {e}")
            return {"target": target, "error": str(e)}

        info(f"Status: {resp.status_code} ({len(resp.content)} bytes)")
        info(f"Final URL: {resp.url}")
        try:
            final_ip = socket.gethostbyname(resp.url.split("://")[1].split("/")[0].split(":")[0])
        except Exception:
            final_ip = "unknown"
        info(f"Final IP: {final_ip}")

        section("Security Headers")
        headers = resp.headers
        present = []
        missing = []

        for header, config in SECURITY_HEADERS.items():
            value = headers.get(header)
            if header == "Set-Cookie":
                continue
            if value:
                if config["good"]:
                    success(f"✓ {header}: {value[:80]}")
                    present.append(header)
                else:
                    warning(f"! {header}: {value[:80]}")
                    present.append(header)
            else:
                if config["good"]:
                    missing.append(header)

        if missing:
            warning(f"\nMissing security headers ({len(missing)}):")
            for h in missing:
                result("", f"{h} - {SECURITY_HEADERS[h]['description']}")

        section("Information Disclosure")
        for info_header in INFO_HEADERS:
            if info_header in headers:
                warning(f"{info_header}: {headers[info_header][:100]}")

        if "Set-Cookie" in headers:
            section("Cookie Security")
            for cookie in resp.cookies:
                flags = []
                if cookie.secure:
                    flags.append("Secure")
                else:
                    warning(f"Cookie '{cookie.name}' missing Secure flag")
                if cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append("HttpOnly")
                else:
                    warning(f"Cookie '{cookie.name}' missing HttpOnly flag")
                result(cookie.name, f"domain={cookie.domain} {' '.join(flags)}")

        info(f"\nAnalysis complete. {len(present)} security headers present, {len(missing)} missing.")
        return {"target": target, "status": resp.status_code, "headers": dict(headers)}
