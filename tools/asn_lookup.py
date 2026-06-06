import socket
import requests
from utils.output import section, info, success, warning, error, result, table


def get_asn_info(target):
    try:
        resp = requests.get(
            f"https://ip-api.com/json/{target}?fields=status,as,org,isp,query",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success" and data.get("as"):
                return {
                    "asn": data.get("as", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "ip": data.get("query", target),
                }
    except:
        pass

    try:
        resp = requests.get(
            f"https://ipwhois.app/json/{target}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") and data.get("asn"):
                return {
                    "asn": f"AS{data.get('asn', '')}",
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "ip": data.get("ip", target),
                }
    except:
        pass

    try:
        resp = requests.get(
            f"https://rdap.arin.net/registry/ip/{target}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "asn": data.get("handle", ""),
                "org": data.get("name", ""),
                "isp": data.get("name", ""),
                "ip": target,
            }
    except:
        pass

    return None


def get_asn_via_bgpview(asn, timeout=15):
    asn_num = asn.replace("AS", "").replace("as", "").strip()
    try:
        resp = requests.get(
            f"https://api.bgpview.io/asn/{asn_num}",
            timeout=timeout,
            headers={"User-Agent": "Reconnor-OSINT/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "asn": f"AS{asn_num}",
                "name": data.get("name", ""),
                "description": data.get("description", ""),
                "country": data.get("country_code", ""),
                "org": data.get("organization", {}).get("name", "") if data.get("organization") else "",
                "ipv4_prefixes": len(data.get("prefixes", [])),
                "ipv6_prefixes": len(data.get("ipv6_prefixes", [])),
            }
        return None
    except:
        return None


def get_asn_ranges(asn, timeout=15):
    asn_num = asn.replace("AS", "").replace("as", "").strip()
    try:
        resp = requests.get(
            f"https://api.bgpview.io/asn/{asn_num}/prefixes",
            timeout=timeout,
            headers={"User-Agent": "Reconnor-OSINT/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            ipv4 = [p.get("prefix", "") for p in data.get("ipv4_prefixes", [])]
            ipv6 = [p.get("prefix", "") for p in data.get("ipv6_prefixes", [])]
            return ipv4, ipv6
        return [], []
    except:
        return [], []


class ASNLookup:
    name = "asn"
    description = "Look up ASN, network ranges, and ISP information"

    @staticmethod
    def run(target):
        section(f"ASN Lookup: {target}")

        if target.upper().startswith("AS"):
            is_asn_query = True
            asn_input = target.upper()
        else:
            is_asn_query = False
            if not target.replace(".", "").isdigit():
                try:
                    ip = socket.gethostbyname(target)
                    info(f"Resolved {target} -> {ip}")
                    target = ip
                except socket.gaierror:
                    error(f"Cannot resolve {target}")
                    return {"target": target, "error": "DNS resolution failed"}

        if is_asn_query:
            asn_data = get_asn_via_bgpview(asn_input)
            if asn_data:
                section(f"ASN Information: {asn_input}")
                result("ASN", asn_data.get("asn", ""))
                result("Name", asn_data.get("name", "N/A"))
                result("Description", asn_data.get("description", "N/A")[:150])
                result("Country", asn_data.get("country", "N/A"))
                result("Organization", asn_data.get("org", "N/A"))
                result("IPv4 Prefixes", str(asn_data.get("ipv4_prefixes", 0)))
                result("IPv6 Prefixes", str(asn_data.get("ipv6_prefixes", 0)))

                section("IP Ranges")
                ipv4_ranges, ipv6_ranges = get_asn_ranges(asn_input)
                if ipv4_ranges:
                    info("IPv4 ranges:")
                    for pfx in ipv4_ranges[:30]:
                        info(f"  {pfx}")
                    if len(ipv4_ranges) > 30:
                        info(f"  ... and {len(ipv4_ranges) - 30} more IPv4 ranges")
                if ipv6_ranges:
                    info("IPv6 ranges:")
                    for pfx in ipv6_ranges[:10]:
                        info(f"  {pfx}")
                    if len(ipv6_ranges) > 10:
                        info(f"  ... and {len(ipv6_ranges) - 10} more IPv6 ranges")
            else:
                error(f"Could not retrieve ASN info for {asn_input}")

            return {"target": target, "asn": asn_input}

        info(f"Looking up ASN for IP {target}...")
        asn_info = get_asn_info(target)

        if not asn_info:
            error(f"Could not get ASN info for {target}")
            return {"target": target, "error": "ASN lookup failed"}

        section("ASN Information")
        result("IP", asn_info.get("ip", ""))
        result("ASN", asn_info.get("asn", "N/A"))
        result("ISP", asn_info.get("isp", "N/A"))
        result("Organization", asn_info.get("org", "N/A"))

        asn_parts = asn_info.get("asn", "").split()
        if asn_parts:
            asn_number = asn_parts[0]
            section("Detailed ASN Data")
            asn_data = get_asn_via_bgpview(asn_number)
            if asn_data:
                result("AS Name", asn_data.get("name", "N/A"))
                result("Country", asn_data.get("country", "N/A"))
                result("IPv4 Prefixes", str(asn_data.get("ipv4_prefixes", 0)))
                result("IPv6 Prefixes", str(asn_data.get("ipv6_prefixes", 0)))

                section("IP Ranges")
                ipv4_ranges, ipv6_ranges = get_asn_ranges(asn_number)
                if ipv4_ranges:
                    info(f"Found {len(ipv4_ranges)} IPv4 range(s):")
                    for pfx in ipv4_ranges[:20]:
                        info(f"  {pfx}")
                    if len(ipv4_ranges) > 20:
                        info(f"  ... and {len(ipv4_ranges) - 20} more")

        return {"target": target, "asn": asn_info}
