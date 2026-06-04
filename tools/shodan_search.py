import os
import requests
import json
from utils.output import section, info, success, warning, error, result, table

SHODAN_API_BASE = "https://api.shodan.io"

def shodan_api_key():
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        try:
            with open(os.path.expanduser("~/.shodan/api_key")) as f:
                key = f.read().strip()
        except Exception:
            pass
    return key

def shodan_host(ip, key):
    try:
        resp = requests.get(f"{SHODAN_API_BASE}/shodan/host/{ip}", params={"key": key}, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            return {"error": "Invalid API key"}
        elif resp.status_code == 403:
            return {"error": "API usage limit exceeded"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def shodan_search(query, key, limit=20):
    try:
        resp = requests.get(
            f"{SHODAN_API_BASE}/shodan/host/search",
            params={"key": key, "query": query, "limit": min(limit, 100)},
            timeout=15
        )
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            return {"error": "Invalid API key"}
        elif resp.status_code == 403:
            return {"error": "API usage limit exceeded"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def shodan_dns_resolve(domain, key):
    try:
        resp = requests.get(
            f"{SHODAN_API_BASE}/dns/resolve",
            params={"key": key, "hostnames": domain},
            timeout=15
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

class ShodanSearch:
    name = "shodan"
    description = "Search Shodan.io for devices, services, and open ports"

    @staticmethod
    def run(target, query=None, limit=20, ollama_model=None):
        section(f"Shodan Search: {target if not query else query}")

        key = shodan_api_key()
        if not key:
            error("No Shodan API key found. Set SHODAN_API_KEY env var or save to ~/.shodan/api_key")
            error("Get a free API key at https://account.shodan.io/")
            return {"target": target, "error": "No API key"}

        if query:
            info(f"Searching Shodan for: {query}")
            results = shodan_search(query, key, limit)
            if "error" in results:
                error(f"Search failed: {results['error']}")
                return {"target": query, "error": results['error']}

            total = results.get("total", 0)
            matches = results.get("matches", [])
            info(f"Total results: {total}")
            info(f"Showing {len(matches)} matches")

            section("Search Results")
            for i, match in enumerate(matches[:limit], 1):
                ip = match.get("ip_str", "?")
                port = match.get("port", "?")
                service = match.get("product", match.get("http", {}).get("title", ""))
                org = match.get("org", "")
                hostnames = ", ".join(match.get("hostnames", [])[:3])
                result(f"{i}. {ip}:{port}", f"{service} [{org}] {hostnames}")

            section("Port/Service Distribution")
            port_counts = {}
            for m in matches:
                p = m.get("port", "?")
                svc = m.get("product", "")
                key_port = f"{p} ({svc})" if svc else str(p)
                port_counts[key_port] = port_counts.get(key_port, 0) + 1
            for p, c in sorted(port_counts.items(), key=lambda x: -x[1]):
                result(f"  Port {p}", str(c))

            section("Top Organizations")
            org_counts = {}
            for m in matches:
                org = m.get("org", "Unknown")
                org_counts[org] = org_counts.get(org, 0) + 1
            for org, c in sorted(org_counts.items(), key=lambda x: -x[1])[:10]:
                result(f"  {org}", str(c))

            if ollama_model:
                try:
                    from utils.ollama_helper import OllamaHelper
                    ollama = OllamaHelper(model=ollama_model)
                    if ollama.available:
                        info("AI analysis of Shodan results...")
                        ai_output = ollama.analyze_shodan_results(matches[:50], query)
                        section("AI Analysis")
                        print(ai_output)
                except Exception as e:
                    warning(f"AI analysis unavailable: {e}")

            return {"target": query, "total": total, "matches": len(matches)}

        if not target.startswith(("http://", "https://")):
            target_to_resolve = target
        else:
            from urllib.parse import urlparse
            target_to_resolve = urlparse(target).netloc or target

        resolved = shodan_dns_resolve(target_to_resolve, key)
        ip = resolved.get(target_to_resolve, target_to_resolve)
        if ip == target_to_resolve:
            try:
                import socket
                ip = socket.gethostbyname(target_to_resolve)
            except Exception:
                pass

        info(f"Looking up Shodan data for {target_to_resolve} ({ip})")
        data = shodan_host(ip, key)

        if "error" in data:
            error(f"Shodan lookup failed: {data['error']}")
            return {"target": target, "error": data['error']}

        if data.get("ports"):
            section("Open Ports")
            result("Ports", ", ".join(str(p) for p in sorted(data["ports"])))

            section("Port Details")
            for service in data.get("data", []):
                port = service.get("port", "?")
                transport = service.get("transport", "")
                product = service.get("product", "")
                version = service.get("version", "")
                hostname = service.get("hostnames", [])
                hostname_str = f" ({', '.join(hostname[:3])})" if hostname else ""
                if product:
                    result(f"  {port}/{transport}", f"{product} {version}{hostname_str}")
                else:
                    result(f"  {port}/{transport}", f"{service.get('_', 'unknown')}{hostname_str}")

        if data.get("hostnames"):
            section("Hostnames")
            for hn in data.get("hostnames", []):
                success(hn)

        section("General Info")
        result("IP", data.get("ip_str", "?"))
        result("Organization", data.get("org", "?"))
        result("ISP", data.get("isp", "?"))
        result("Country", data.get("country_name", "?"))
        result("City", data.get("city", "?"))
        result("ASN", f"AS{data.get('asn', '?')}")
        result("Operating System", data.get("os", "Unknown"))

        if data.get("vulns"):
            section("Vulnerabilities")
            for vuln in data.get("vulns", []):
                warning(vuln)

        if ollama_model:
            try:
                from utils.ollama_helper import OllamaHelper
                ollama = OllamaHelper(model=ollama_model)
                if ollama.available:
                    info("AI analysis of host data...")
                    ai_output = ollama.analyze_shodan_host(data)
                    section("AI Analysis")
                    print(ai_output)
            except Exception as e:
                warning(f"AI analysis unavailable: {e}")

        return {"target": target, "ip": ip, "data": data}
