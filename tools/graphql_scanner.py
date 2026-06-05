import json
import urllib.request
import urllib.parse
import re
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

        if not target_url.endswith("/graphql"):
            candidates = ["/graphql", "/api", "/graph", "/query", "/v1/graphql", "/v2/graphql", "/api/graphql"]
            for c in candidates:
                test = target_url.rstrip("/") + c
                try:
                    req = urllib.request.Request(test, json.dumps({"query": "query{__typename}"}).encode(), {"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status == 200:
                            target_url = test
                            info(f"Discovered GraphQL endpoint: {target_url}")
                            break
                except:
                    continue
            else:
                error("Could not discover GraphQL endpoint")
                return {"error": "no graphql endpoint"}

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
            resp = GraphQLScanner._gql_call(target_url, GraphQLScanner.INTROSPECTION_QUERY, timeout)
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
                        req = urllib.request.Request(target_url, payload.encode(), {"Content-Type": "application/json"})
                    else:
                        req = payload
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status == 200:
                            warning(f"Batch query accepted ({resp.status})")
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
                    req = urllib.request.Request(target_url, json.dumps({"query": payload}).encode(), {"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=timeout * 2) as resp:
                        body = json.loads(resp.read())
                        if resp.status == 200 and "data" in body and body["data"]:
                            depth = [5, 11][i]
                            result_data["depth_limit"]["vulnerable"] = True
                            result_data["depth_limit"]["max_depth"] = max(result_data["depth_limit"]["max_depth"], depth)
                            warning(f"No depth limit! Depth {depth} succeeded")
                except:
                    success(f"Depth limit enforced at level {'5' if i == 0 else '11'}")

            try:
                req = urllib.request.Request(target_url, json.dumps({"query": GraphQLScanner.ALIAS_BOMB}).encode(), {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout * 2) as resp:
                    if resp.status == 200:
                        warning("Alias bomb succeeded — possible DoS vector")
                        result_data["alias_bomb"] = True
            except:
                success("Alias bombing rejected")

        if auth_bypass:
            section("Auth Bypass Testing")
            methods = [
                ("GET with query param", lambda: urllib.request.Request(f"{target_url}?query={urllib.parse.quote('query{__typename}')}")),
                ("No content-type", lambda: urllib.request.Request(target_url, b'{"query":"query{__typename}"}')),
                ("Alternative CT", lambda: urllib.request.Request(target_url, b'{"query":"query{__typename}"}', {"Content-Type": "text/plain"})),
                ("Accept any", lambda: urllib.request.Request(target_url, json.dumps({"query": "mutation{__typename}"}).encode(), {"Content-Type": "application/json", "Accept": "*/*"})),
            ]
            for name, builder in methods:
                try:
                    req = builder()
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status == 200:
                            finding = {"method": name, "status": resp.status}
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
    def _gql_call(url, query, timeout):
        try:
            req = urllib.request.Request(url, json.dumps({"query": query}).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except:
            return None

    @staticmethod
    def _wrap_batch(url, count, timeout):
        queries = [{"query": f"query{{a{i}:__typename}}", "variables": {}} for i in range(count)]
        return json.dumps(queries)
