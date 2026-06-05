import socket
import struct
import threading
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.output import section, info, success, warning, error, result, table


class NetworkScan:
    description = "Advanced network scanner: ARP discovery, ping sweep, OS fingerprinting, port scanning"

    OS_TTL_MAP = {
        64: "Linux/Unix/macOS",
        128: "Windows",
        255: "Cisco/Network",
        60: "AIX",
        254: "Solaris",
    }

    @staticmethod
    def run(target="", subnet="", ports="22,80,443,3306,3389,8080,8443", ping=True, arp=False, os_detect=False, threads=100, timeout=5, **kwargs):
        section("Network Scanner")

        if not target and not subnet:
            error("No target or subnet (use --target or --subnet)")
            return {"error": "no target"}

        result_data = {"live_hosts": [], "os_guesses": [], "open_ports": [], "arp_entries": []}

        hosts = []
        if target:
            hosts.append(target)
        if subnet:
            hosts.extend(NetworkScan._expand_subnet(subnet))

        if not hosts:
            error("No hosts to scan")
            return {"error": "no hosts"}

        section(f"Scanning {len(hosts)} host(s)")

        # ARP discovery
        if arp:
            section("ARP Discovery")
            try:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=timeout)
                for line in result.stdout.split("\n"):
                    match = re.search(r"\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)", line, re.I)
                    if match:
                        entry = {"ip": match.group(1), "mac": match.group(2)}
                        result_data["arp_entries"].append(entry)
                        info(f"ARP: {entry['ip']} -> {entry['mac']}")
            except:
                warning("ARP scan failed (try as root)")

        # Ping sweep
        if ping:
            section("Ping Sweep")
            live = []

            def ping_host(h):
                try:
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", str(timeout), h],
                        capture_output=True, text=True, timeout=timeout + 2,
                    )
                    if result.returncode == 0:
                        return h, True
                except:
                    pass
                return h, False

            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = [ex.submit(ping_host, h) for h in hosts]
                for f in as_completed(futures):
                    h, alive = f.result()
                    if alive:
                        live.append(h)
                        success(f"Host alive: {h}")

            hosts = live if live else hosts

        # OS fingerprinting
        if os_detect and hosts:
            section("OS Fingerprinting")
            for h in hosts:
                os = NetworkScan._fingerprint_os(h, timeout)
                if os:
                    result_data["os_guesses"].append({"host": h, "os": os})
                    result(f"{h}", os)

        # Port scan
        section("Port Scanning")
        port_list = NetworkScan._parse_ports(ports)

        def scan_port(h, p):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((h, p))
                sock.close()
                return h, p, True
            except:
                return h, p, False

        scanned = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for h in hosts:
                for p in port_list:
                    futures.append(ex.submit(scan_port, h, p))

            for f in as_completed(futures):
                h, p, open_port = f.result()
                if open_port:
                    scanned.append({"host": h, "port": p})
                    result_data["open_ports"].append({"host": h, "port": p})
                    info(f"{h}:{p} open")

        section("Network Scan Complete")
        result_data["alive_count"] = len(hosts)
        success(f"{len(hosts)} hosts alive, {len(result_data['open_ports'])} open ports found")

        if result_data["open_ports"]:
            rows = [[s["host"], str(s["port"])] for s in result_data["open_ports"]]
            table(["Host", "Port"], rows)

        return result_data

    @staticmethod
    def _expand_subnet(subnet):
        hosts = []
        try:
            if "/" in subnet:
                ip, bits = subnet.split("/")
                bits = int(bits)
                host_bits = 32 - bits
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
                network = ip_int & mask
                for i in range(1, 2**host_bits - 1):
                    host_int = network | i
                    hosts.append(socket.inet_ntoa(struct.pack("!I", host_int)))
                    if len(hosts) > 256:  # limit
                        break
        except:
            pass
        return hosts

    @staticmethod
    def _parse_ports(ports):
        result = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-")
                    result.extend(range(int(lo), int(hi) + 1))
                except:
                    pass
            else:
                try:
                    result.append(int(part))
                except:
                    pass
        return result

    @staticmethod
    def _fingerprint_os(host, timeout):
        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            sock.connect((host, 1))
            sock.close()
        except:
            pass

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, 80))
            ttl = 64
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout + 2,
            )
            ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.I)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                return NetworkScan.OS_TTL_MAP.get(ttl, f"Unknown (TTL={ttl})")
            sock.close()
        except:
            pass
        return None
