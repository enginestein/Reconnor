import json
import time
import urllib.request
import urllib.parse
import re
from utils.output import section, info, success, warning, error, result, table


class APIFuzzer:
    description = "Advanced REST/GraphQL API fuzzer: header injection, param pollution, rate limit testing"

    HEADER_INJECTION = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-Host", "evil.com"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Forwarded-Proto", "http"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Scheme", "http"),
        ("X-API-Key", "test"),
        ("Authorization", "Bearer test"),
        ("X-Auth-Token", "test"),
    ]

    PARAM_POLLUTION = [
        "?id=1&id=2",
        "?id=1&id[]=2",
        "?user=admin&user=guest",
        "?debug=true&debug=false",
        "?admin=true",
        "?dev=true",
    ]

    RATE_LIMIT_PATTERNS = [
        "rate.limit", "too many", "429", "throttl", "retry-after",
        "try again", "slow down", "blocked", "exceeded",
    ]

    @staticmethod
    def run(url="", target="", method="GET", data="", headers_json="", params="", threads=20, timeout=15, rate_limit=False, pollute=False, inject_headers=False, **kwargs):
        section("API Fuzzer")

        target_url = url or target or ""
        if not target_url:
            error("No target URL")
            return {"error": "no target"}

        result_data = {
            "target": target_url,
            "injection_findings": [],
            "pollution_findings": [],
            "rate_limit": {"limited": False, "limit": None, "requests_per_second": 0},
        }

        custom_headers = {}
        if headers_json:
            try:
                custom_headers = json.loads(headers_json)
            except:
                warning("Invalid headers JSON")

        if inject_headers:
            section("Header Injection Tests")
            for hdr, val in APIFuzzer.HEADER_INJECTION:
                test_headers = {**custom_headers, hdr: val}
                try:
                    req = urllib.request.Request(target_url, headers=test_headers)
                    if method == "POST":
                        req.method = "POST"
                        if data:
                            req.data = data.encode()
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace").lower()
                        if val.lower() in body:
                            finding = {"header": hdr, "value": val, "reflected": True}
                            result_data["injection_findings"].append(finding)
                            warning(f"Header reflected: {hdr}: {val}")
                        else:
                            info(f"Header sent: {hdr}: {val} (not reflected)")
                except urllib.error.HTTPError as e:
                    if e.code == 200:
                        body = e.read().decode("utf-8", errors="replace").lower()
                        if val.lower() in body:
                            result_data["injection_findings"].append({"header": hdr, "value": val, "reflected": True})
                            warning(f"Header reflected in error: {hdr}: {val}")
                except:
                    info(f"Header {hdr}: connection issue")

        if pollute:
            section("Parameter Pollution Tests")
            base = target_url.split("?")[0]
            for pollution in APIFuzzer.PARAM_POLLUTION:
                test_url = base + pollution
                try:
                    req = urllib.request.Request(test_url, headers=custom_headers)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")[:300]
                        interesting = APIFuzzer._find_interesting(body)
                        if interesting:
                            finding = {"url": test_url, "interesting": interesting, "status": resp.status}
                            result_data["pollution_findings"].append(finding)
                            warning(f"Pollution vector: {pollution}")
                            info(f"  Interesting: {', '.join(interesting[:3])}")
                except:
                    pass

        if rate_limit:
            section("Rate Limit Testing")
            success_count = 0
            for burst_size in [10, 25, 50, 100, 200]:
                try:
                    start = __import__("time").time()
                    for _ in range(burst_size):
                        try:
                            req = urllib.request.Request(target_url, headers=custom_headers)
                            with urllib.request.urlopen(req, timeout=timeout / 2) as resp:
                                body = resp.read().decode("utf-8", errors="replace").lower()
                                for pattern in APIFuzzer.RATE_LIMIT_PATTERNS:
                                    if pattern in body:
                                        rps = burst_size / (time.time() - start)
                                        result_data["rate_limit"]["limited"] = True
                                        result_data["rate_limit"]["limit"] = burst_size
                                        result_data["rate_limit"]["requests_per_second"] = round(rps, 1)
                                        warning(f"Rate limit at ~{burst_size} requests ({rps:.0f} req/s)")
                                        return result_data
                        except urllib.error.HTTPError as e:
                            if e.code == 429:
                                result_data["rate_limit"]["limited"] = True
                                result_data["rate_limit"]["limit"] = burst_size
                                warning(f"HTTP 429 at burst size {burst_size}")
                                return result_data
                        except:
                            pass
                except:
                    pass
            success("No rate limiting detected (burst up to 200 requests)")

        section("API Fuzzing Complete")
        return result_data

    @staticmethod
    def _find_interesting(body):
        keywords = ["admin", "debug", "internal", "secret", "token", "api_key", "password",
                     "config", ".env", "backup", "root", "flag", "user", "bypass"]
        found = []
        for kw in keywords:
            if kw in body.lower():
                found.append(kw)
        return found
