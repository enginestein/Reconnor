import socket
from utils.output import section, info, success, warning, error, result, table

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]


def resolve_with_socket(hostname, record_type="A"):
    try:
        if record_type == "A":
            return [socket.gethostbyname(hostname)]
        elif record_type == "AAAA":
            return []
        else:
            return []
    except socket.gaierror:
        return []


def resolve_with_dnspython(hostname, record_type):
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=5)
        return [str(r) for r in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        return []


def resolve_record(hostname, record_type):
    if HAS_DNSPYTHON:
        return resolve_with_dnspython(hostname, record_type)
    else:
        return resolve_with_socket(hostname, record_type)


def try_zone_transfer(domain, ns):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
        if zone:
            return [str(name) + "." + domain for name in zone.nodes.keys()]
    except Exception:
        pass
    return []


class DNSRecon:
    name = "dns"
    description = "DNS enumeration and reconnaissance"

    @staticmethod
    def run(target, zone_transfer=False):
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target
        section(f"DNS Reconnaissance: {target}")

        if not HAS_DNSPYTHON:
            warning("dnspython not installed - limited DNS resolution. Install with: pip install dnspython")

        for rtype in RECORD_TYPES:
            records = resolve_record(target, rtype)
            if records is None:
                warning(f"{rtype}: Domain does not exist (NXDOMAIN)")
                return {"target": target, "error": "NXDOMAIN"}
            if records:
                success(f"{rtype} Records:")
                for r in records:
                    result("", r)
            else:
                info(f"{rtype}: No records found")

        if zone_transfer and HAS_DNSPYTHON:
            section("Zone Transfer Attempt")
            ns_records = resolve_record(target, "NS")
            for ns in ns_records:
                info(f"Attempting zone transfer on {ns}...")
                try:
                    ns_ip = socket.gethostbyname(ns)
                    records = try_zone_transfer(target, ns_ip)
                    if records:
                        success(f"Zone transfer successful from {ns}!")
                        for r in records:
                            result("", r)
                    else:
                        info(f"Zone transfer refused by {ns}")
                except:
                    warning(f"Could not connect to {ns}")

        try:
            ip = socket.gethostbyname(target)
            info(f"\nReverse DNS for {ip}:")
            try:
                host = socket.gethostbyaddr(ip)
                result("PTR", host[0])
            except socket.herror:
                warning("No PTR record found")
        except socket.gaierror:
            error("Could not resolve target")

        return {"target": target}
