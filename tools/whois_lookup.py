import socket
import subprocess
import re

from utils.output import section, info, success, warning, error, result


def whois_via_socket(domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"


def whois_via_command(domain):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout
        return result.stderr
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return "Timeout: whois query took too long"


def parse_whois_basic(data):
    interesting = [
        "Domain Name:", "Registry Domain ID:", "Registrar:",
        "Registrar IANA ID:", "Registrar Abuse Contact Email:",
        "Registrar Abuse Contact Phone:", "Registrant Name:",
        "Registrant Organization:", "Registrant Country:",
        "Admin Name:", "Admin Organization:", "Admin Email:",
        "Tech Name:", "Tech Organization:", "Tech Email:",
        "Name Server:", "Creation Date:", "Registry Expiry Date:",
        "Updated Date:", "DNSSEC:", "Status:",
        "Registrar Registration Expiration Date:",
        "Registrar WHOIS Server:",
    ]
    lines = data.split("\n")
    parsed = {}
    for line in lines:
        for key in interesting:
            if line.strip().startswith(key):
                val = line.strip()[len(key):].strip()
                if key not in parsed:
                    parsed[key] = val
                else:
                    if isinstance(parsed[key], str):
                        parsed[key] = [parsed[key], val]
                    else:
                        parsed[key].append(val)
    return parsed


class WhoisLookup:
    name = "whois"
    description = "WHOIS lookup for domain or IP addresses"

    @staticmethod
    def run(target):
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target
        section(f"WHOIS Lookup: {target}")

        is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", target)

        if is_ip:
            data = whois_via_socket(target)
        else:
            data = whois_via_command(target)
            if data is None:
                info("whois command not found, using socket fallback...")
                data = whois_via_socket(target)

        if not data or data.startswith("Error") or data.startswith("Timeout"):
            error(f"WHOIS lookup failed: {data}")
            return {"target": target, "error": data}

        if is_ip:
            info(f"WHOIS data for IP {target}:")
            print(data[:2000])
        else:
            parsed = parse_whois_basic(data)
            if parsed:
                info("Parsed WHOIS Information:")
                for key, val in parsed.items():
                    if isinstance(val, list):
                        for v in val:
                            result(key.rstrip(":"), v)
                    else:
                        result(key.rstrip(":"), val)
                info("\nRaw WHOIS output also available below:")
            print(data[:3000])

        return {"target": target, "raw": data[:3000]}
