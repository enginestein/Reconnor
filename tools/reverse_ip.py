import socket
import requests
from utils.output import section, info, success, warning, error, result, table


def reverse_ip_via_http(ip, timeout=15):
    try:
        resp = requests.get(
            f"https://json.ip.sb/ip/{ip}",
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            if "domains" in data:
                return data["domains"]
        return None
    except:
        return None


def reverse_ip_via_viewdns(ip, timeout=15):
    try:
        resp = requests.get(
            f"https://api.viewdns.info/reverseip/?host={ip}&output=json",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            domains = data.get("response", {}).get("domains", [])
            return [d.get("name", "") for d in domains]
        return None
    except:
        return None


def reverse_ip_via_hackertarget(ip, timeout=15):
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            if len(lines) > 1 and not lines[0].startswith("API"):
                return [l.strip() for l in lines if l.strip() and not l.strip().startswith("No")]
        return None
    except:
        return None


def resolve_to_ip(target):
    try:
        if target.replace(".", "").isdigit():
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


class ReverseIP:
    name = "reverseip"
    description = "Find domains/sites hosted on the same IP address (reverse IP lookup)"

    @staticmethod
    def run(target):
        section(f"Reverse IP Lookup: {target}")

        ip = resolve_to_ip(target)
        if not ip:
            error(f"Cannot resolve {target}")
            return {"target": target, "error": "DNS resolution failed"}

        info(f"Target IP: {ip}")
        all_domains = set()
        sources_used = []

        info("Querying sources for co-hosted domains...")

        result_data = reverse_ip_via_hackertarget(ip)
        if result_data:
            sources_used.append("hackertarget.com")
            for d in result_data:
                if d and not d.startswith("API"):
                    all_domains.add(d.lower())
            success(f"hackertarget.com: {len(result_data)} domains")

        result_data = reverse_ip_via_http(ip)
        if result_data:
            sources_used.append("ip.sb")
            for d in result_data:
                all_domains.add(d.lower())
            success(f"ip.sb: {len(result_data)} domains")

        if not all_domains:
            warning("No co-hosted domains found from any source")
            return {"target": target, "ip": ip, "domains": []}

        section(f"Domains on {ip} ({len(all_domains)} found)")
        sorted_domains = sorted(all_domains)
        for i, domain in enumerate(sorted_domains[:100], 1):
            result(f"  {i:3d}.", domain)

        if len(sorted_domains) > 100:
            info(f"... and {len(sorted_domains) - 100} more domains")

        tld_count = {}
        for d in sorted_domains:
            parts = d.split(".")
            tld = ".".join(parts[-2:]) if len(parts) >= 2 else d
            tld_count[tld] = tld_count.get(tld, 0) + 1

        section("Top-Level Distribution")
        for tld, count in sorted(tld_count.items(), key=lambda x: -x[1])[:15]:
            result(tld, str(count))

        return {"target": target, "ip": ip, "domains": sorted_domains}

