import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table
from utils.external_tools import nmap_scan, find_tool

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 514: "Syslog", 587: "SMTP STARTTLS",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel SSL", 2181: "ZooKeeper", 2222: "SSH alt",
    2375: "Docker", 2376: "Docker SSL", 3128: "Squid Proxy",
    3306: "MySQL", 3389: "RDP", 3689: "DAAP", 4369: "Erlang",
    5000: "Flask Dev", 5432: "PostgreSQL", 5555: "ADB",
    5800: "VNC HTTP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6443: "Kubernetes", 7077: "Spark", 8000: "HTTP alt",
    8009: "AJP", 8080: "HTTP Proxy", 8443: "HTTPS alt",
    8888: "HTTP alt", 9000: "SonarQube", 9042: "Cassandra",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9418: "Git", 9999: "Custom", 11211: "Memcached",
    27017: "MongoDB", 50070: "HDFS", 61616: "ActiveMQ",
}



def grab_banner(host, port, timeout=3):
    banners = []
    for proto_name, proto_type in [("HTTP", socket.SOCK_STREAM), ("TLS", socket.SOCK_STREAM)]:
        try:
            s = socket.socket(socket.AF_INET, proto_type)
            s.settimeout(timeout)
            s.connect((host, port))
            if proto_name == "HTTP":
                s.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            data = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            if data:
                banners.append(data[:120])
                if proto_name == "HTTP":
                    break
        except:
            pass
    return banners[0] if banners else None


def scan_port(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(host, port)
            return port, service, banner
    except:
        pass
    return None


class PortScanner:
    name = "port-scan"
    description = "Scan open ports on a target host"

    @staticmethod
    def run(target, ports=None, timeout=2, threads=100, nmap=False):
        section(f"Port Scan: {target}")

        if nmap:
            section("Nmap Service/Version Detection")
            if not find_tool("nmap"):
                warning("nmap not found. Install with: apt install nmap")
            else:
                nmap_results = nmap_scan(target, ports)
                if nmap_results:
                    success(f"nmap found {len(nmap_results)} open port(s):")
                    table(
                        ["PORT", "STATE", "SERVICE", "VERSION"],
                        [(f"{p}/tcp", "open", svc, ver) for p, svc, ver, _ in nmap_results]
                    )
                    info("nmap scan complete")
                    return {"target": target, "nmap_results": nmap_results}
                else:
                    warning("nmap returned no results (may need root)")
            info("Falling back to built-in scanner...")

        port_list = []
        if ports:
            for part in ports.split(","):
                if "-" in part:
                    a, b = part.split("-")
                    port_list.extend(range(int(a), int(b) + 1))
                else:
                    port_list.append(int(part))
        else:
            port_list = list(COMMON_PORTS.keys())

        info(f"Scanning {len(port_list)} ports on {target}...")

        open_ports = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, target, p, timeout): p for p in port_list}
            for i, future in enumerate(as_completed(futures)):
                futures_done = i + 1
                if futures_done % 20 == 0 or futures_done == len(port_list):
                    pass
                result_port = future.result()
                if result_port:
                    port, service, banner = result_port
                    open_ports.append((port, service, banner or ""))

        if open_ports:
            success(f"Found {len(open_ports)} open port(s):")
            table(
                ["PORT", "STATE", "SERVICE", "BANNER"],
                [(f"{p}/tcp", "open", svc, bnr if bnr else "-") for p, svc, bnr in open_ports]
            )
        else:
            warning("No open ports found or host unreachable")

        info(f"Scan complete: {len(open_ports)}/{len(port_list)} ports open")
        return {"target": target, "open_ports": open_ports}
