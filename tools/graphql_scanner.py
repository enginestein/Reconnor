import json
import re
import requests
from utils.output import section, info, success, warning, error, result, table


class GraphQLScanner:
    description = "Advanced GraphQL security scanner: introspection, batching, query depth, auth bypass"

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind name description
          fields(includeDeprecated: true) {
            name description args { name type { kind name ofType { kind name } } }
            type { kind name ofType { kind name } }
          }
        }
        directives { name description locations args { name } }
      }
    }"""

    DISCOVERY_PATHS = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/gql", "/query", "/api", "/graph", "/v1", "/v2",
    ]

    BATCH_PAYLOADS = [
        '[{"query":"query{__typename}","variables":{}},{"query":"query{__typename}","variables":{}}]',
        '{"queries":[{"query":"query{__typename}"},{"query":"query{__typename}"}]}',
        '{"batch":[{"query":"query{__typename}"},{"query":"query{__typename}"}]}',
    ]

    DEPTH_PAYLOADS = [
        "query{__typename{__typename{__typename{__typename{__typename}}}}}",
        "query{q{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename}}}}}}}}}}}}",
    ]

    ALIAS_BOMB = "query{" + "a{}".join(f"a{i}:__typename" for i in range(50)) + "}"

    @staticmethod
    def run(url="", target="", query="", introspection=True, batch=True, depth=True, auth_bypass=False, timeout=15, threads=10, **kwargs):
        section("GraphQL Security Scanner")

        target_url = url or target or ""
        if not target_url:
            error("No target URL (use --url)")
            return {"error": "no target"}

        discovered = None
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Content-Type": "application/json",
        }

        if target_url.endswith("/graphql"):
            candidates = [target_url]
        else:
            base = target_url.rstrip("/")
            candidates = [base + p for p in GraphQLScanner.DISCOVERY_PATHS]

        section("Endpoint Discovery")
        for test_url in candidates:
            try:
                resp = requests.post(
                    test_url,
                    json={"query": "query{__typename}"},
                    headers=headers,
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        if "data" in data and data["data"] is not None:
                            discovered = test_url
                            info(f"GraphQL endpoint found: {discovered}")
                            break
            except (requests.RequestException, json.JSONDecodeError, ValueError):
                continue

        if not discovered:
            section("Introspection Probe")
            for test_url in candidates:
                try:
                    resp = requests.post(
                        test_url,
                        json={"query": GraphQLScanner.INTROSPECTION_QUERY},
                        headers=headers,
                        timeout=timeout * 2,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict) and data.get("data", {}).get("__schema"):
                            discovered = test_url
                            success(f"Valid GraphQL endpoint confirmed via introspection: {discovered}")
                            break
                except (requests.RequestException, json.JSONDecodeError, ValueError):
                    continue

        if not discovered:
            error("No GraphQL endpoint found")
            return {"error": "no graphql endpoint found"}

        target_url = discovered
        result_data = {
            "endpoint": target_url,
            "introspection": {"available": False, "types": [], "mutations": [], "subscriptions": []},
            "batching": {"vulnerable": False, "findings": []},
            "depth_limit": {"vulnerable": False, "max_depth": 0},
            "alias_bomb": False,
            "auth_bypass": {"vulnerable": False, "methods_tested": []},
        }

        if introspection:
            section("Introspection")
            resp = GraphQLScanner._gql_call_requests(target_url, GraphQLScanner.INTROSPECTION_QUERY, timeout)
            if resp and "data" in resp and resp["data"].get("__schema"):
                success("Introspection enabled!")
                schema = resp["data"]["__schema"]
                types = [t["name"] for t in schema.get("types", []) if t["name"] and not t["name"].startswith("__")]
                mutations = [f["name"] for f in (schema.get("mutationType") or {}).get("fields", [])] if schema.get("mutationType") else []
                subscriptions = [f["name"] for f in (schema.get("subscriptionType") or {}).get("fields", [])] if schema.get("subscriptionType") else []
                result_data["introspection"]["available"] = True
                result_data["introspection"]["types"] = types
                result_data["introspection"]["mutations"] = mutations
                result_data["introspection"]["subscriptions"] = subscriptions
                info(f"Found {len(types)} types, {len(mutations)} mutations")
                for m in mutations[:10]:
                    result("Mutation", m)
            else:
                warning("Introspection disabled (good)")

        if batch:
            section("Batch Attack Testing")
            payloads = GraphQLScanner.BATCH_PAYLOADS + [
                GraphQLScanner._wrap_batch(target_url, 10, timeout),
            ]
            for payload in payloads:
                try:
                    if isinstance(payload, str):
                        req_data = payload
                    else:
                        req_data = payload
                    resp = requests.post(target_url, data=req_data if isinstance(req_data, str) else None,
                        json=None if isinstance(req_data, str) else req_data,
                        headers={"Content-Type": "application/json", "User-Agent": headers["User-Agent"]},
                        timeout=timeout)
                    if resp.status_code == 200:
                        warning(f"Batch query accepted ({resp.status_code})")
                        result_data["batching"]["vulnerable"] = True
                        result_data["batching"]["findings"].append(f"Batch accepted: {payload[:80]}")
                        break
                except:
                    continue
            else:
                success("Batch attacks rejected")

        if depth:
            section("Query Depth Analysis")
            for i, payload in enumerate(GraphQLScanner.DEPTH_PAYLOADS):
                try:
                    resp = requests.post(target_url, json={"query": payload},
                        headers=headers, timeout=timeout * 2)
                    if resp.status_code == 200:
                        body = resp.json()
                        if "data" in body and body["data"]:
                            depths = [5, 11]
                            result_data["depth_limit"]["vulnerable"] = True
                            result_data["depth_limit"]["max_depth"] = max(result_data["depth_limit"]["max_depth"], depths[i])
                            warning(f"No depth limit! Depth {depths[i]} succeeded")
                except:
                    success(f"Depth limit enforced at level {'5' if i == 0 else '11'}")

            try:
                resp = requests.post(target_url, json={"query": GraphQLScanner.ALIAS_BOMB},
                    headers=headers, timeout=timeout * 2)
                if resp.status_code == 200:
                    warning("Alias bomb succeeded — possible DoS vector")
                    result_data["alias_bomb"] = True
            except:
                success("Alias bombing rejected")

        if auth_bypass:
            section("Auth Bypass Testing")
            methods = [
                ("GET with query param", f"{target_url}?query={json.dumps('query{__typename}')}"),
                ("No content-type", (target_url, json.dumps({"query": "query{__typename}"}))),
                ("Alternative CT", (target_url, json.dumps({"query": "query{__typename}"}), {"Content-Type": "text/plain"})),
                ("Accept any", (target_url, json.dumps({"query": "mutation{__typename}"}), {"Content-Type": "application/json", "Accept": "*/*"})),
            ]
            for name, req_config in methods:
                try:
                    if isinstance(req_config, str):
                        resp = requests.get(req_config, headers=headers, timeout=timeout)
                    elif len(req_config) == 2:
                        resp = requests.post(req_config[0], data=req_config[1], timeout=timeout)
                    else:
                        url, data, extra_headers = req_config
                        merged_headers = {"User-Agent": headers["User-Agent"]}
                        merged_headers.update(extra_headers)
                        resp = requests.post(url, data=data, headers=merged_headers, timeout=timeout)
                    if resp.status_code == 200:
                        finding = {"method": name, "status": resp.status_code}
                        result_data["auth_bypass"]["findings"].append(finding)
                        result_data["auth_bypass"]["vulnerable"] = True
                        warning(f"Auth bypass: {name}")
                except:
                    pass

        section("GraphQL Scan Complete")
        if result_data["introspection"]["available"]:
            warning("INTROSPECTION ENABLED — disable in production")
        if result_data["batching"]["vulnerable"]:
            warning("BATCHING VULNERABLE — implement rate limiting")
        if result_data["depth_limit"]["vulnerable"]:
            warning(f"DEPTH LIMIT INSUFFICIENT — max depth {result_data['depth_limit']['max_depth']}")
        if result_data["auth_bypass"]["vulnerable"]:
            warning("AUTH BYPASS POSSIBLE")

        return result_data

    @staticmethod
    def _gql_call_requests(url, query, timeout):
        try:
            resp = requests.post(url, json={"query": query},
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                timeout=timeout)
            return resp.json()
        except:
            return None

    @staticmethod
    def _wrap_batch(url, count, timeout):
        queries = [{"query": f"query{{a{i}:__typename}}", "variables": {}} for i in range(count)]
        return json.dumps(queries)
