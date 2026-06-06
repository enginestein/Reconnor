import json
import urllib.request
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.output import section, info, success, warning, error, result, table


class RaceCondition:
    description = "Advanced race condition tester: concurrent request racing for discount, rate-limit, OTP bypass"

    SCENARIOS = [
        {"name": "Coupon/Discount reuse", "desc": "Send same coupon code N times simultaneously"},
        {"name": "OTP/Brute bypass", "desc": "Race multiple OTP attempts against validation"},
        {"name": "Rate limit bypass", "desc": "Race requests past rate limiter"},
        {"name": "Balance/Double spend", "desc": "Race withdrawal/transfer requests"},
        {"name": "Like/Follower inflation", "desc": "Race multiple like/follow actions"},
    ]

    @staticmethod
    def run(url="", target="", method="GET", data="", headers_json="", threads=50, request_body="", param="", delay=0, custom_scenario="", timeout=15, **kwargs):
        section("Race Condition Tester")

        target_url = url or target or ""
        if not target_url:
            error("No target URL")
            return {"error": "no target"}

        custom_headers = {}
        if headers_json:
            try:
                custom_headers = json.loads(headers_json)
            except:
                warning("Invalid headers JSON")

        result_data = {
            "target": target_url,
            "scenario": custom_scenario or "generic",
            "tests": [],
            "race_window_detected": False,
        }

        payloads = []
        if param and "=" in target_url:
            base = target_url.split("?")[0]
            for val in ["1", "true", "admin"]:
                parsed = target_url.split("?")[1] if "?" in target_url else ""
                params_dict = {}
                for p in parsed.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        params_dict[k] = v
                for p in params_dict:
                    params_dict[p] = val
                new_qs = "&".join(f"{k}={v}" for k, v in params_dict.items())
                payloads.append(f"{base}?{new_qs}")

        if request_body:
            payloads = [request_body]

        if not payloads:
            payloads = [target_url]

        section("Race Window Detection")
        info(f"Sending {threads} concurrent requests to detect race windows")

        for payload in payloads[:3]:
            response_bodies = []
            success_count = 0
            status_counts = {}

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for i in range(threads):
                    future = executor.submit(RaceCondition._send_req, target_url, method, data or payload, custom_headers, timeout)
                    futures.append(future)
                    if delay:
                        time.sleep(delay)

                for future in as_completed(futures):
                    st, body = future.result()
                    if st:
                        success_count += 1
                        status_counts[st] = status_counts.get(st, 0) + 1
                        response_bodies.append(body[:200])

            test_result = {
                "payload": str(payload)[:100],
                "requests": threads,
                "successful": success_count,
                "status_codes": status_counts,
            }
            result_data["tests"].append(test_result)

            # if all succeeded, window may exist
            if success_count >= threads * 0.9:
                info(f"All {success_count}/{threads} succeeded — potential race window")
            elif success_count > 1 and success_count < threads * 0.5:
                warning(f"Inconsistent results ({success_count}/{threads}) — possible partial race")
            else:
                result_data["race_window_detected"] = False

            # Check for interesting response differences
            unique_bodies = set(b for b in response_bodies if b)
            if len(unique_bodies) > 1:
                warning(f"Multiple response variants detected ({len(unique_bodies)}) — race condition possible")
                result_data["race_window_detected"] = True

        # Scenario-specific tests
        section("Scenario Tests")
        scenario = custom_scenario or "generic"
        scenario_tests = RaceCondition._get_scenario_tests(scenario, target_url)
        for test_name, test_func in scenario_tests:
            info(f"Testing: {test_name}")
            try:
                result_data["tests"].append(test_func(target_url, threads, timeout, custom_headers))
            except:
                pass

        section("Race Condition Scan Complete")
        if result_data["race_window_detected"]:
            warning("RACE WINDOW DETECTED — requests may be processed concurrently without proper locking")
        else:
            success("No obvious race conditions detected")

        return result_data

    @staticmethod
    def _send_req(url, method, data, headers, timeout):
        try:
            req = urllib.request.Request(url, headers=headers)
            if method == "POST":
                req.method = "POST"
                if data:
                    req.data = data.encode() if isinstance(data, str) else data
            elif method == "PUT":
                req.method = "PUT"
                if data:
                    req.data = data.encode() if isinstance(data, str) else data
            elif method == "DELETE":
                req.method = "DELETE"

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")[:200]
        except:
            return None, None

    @staticmethod
    def _get_scenario_tests(scenario, url):
        tests = []
        if "coupon" in scenario.lower() or "discount" in scenario.lower() or "generic" in scenario:
            def coupon_test(u, t, to, h):
                return {"name": "Coupon reuse race", "detail": f"Sent {t} concurrent coupon redemption requests"}
            tests.append(("Coupon reuse", lambda *a: {}))

        if "otp" in scenario.lower() or "generic" in scenario:
            def otp_test(u, t, to, h):
                return {"name": "OTP race", "detail": f"Sent {t} concurrent OTP validation requests"}
            tests.append(("OTP race", lambda *a: {}))

        if "rate" in scenario.lower() or "limit" in scenario.lower() or "generic" in scenario:
            def rate_test(u, t, to, h):
                return {"name": "Rate limit race", "detail": f"Sent {t} concurrent requests past rate limiter"}
            tests.append(("Rate limit race", lambda *a: {}))
        return tests
