import shutil
import subprocess
import json
import re
from utils.output import info, success, warning, error


_TOOL_CACHE = {}


def find_tool(name):
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name) is not None
    return _TOOL_CACHE[name]


def run_tool(args, timeout=120, text=True):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=text,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return None, "Tool not found", -1
    except subprocess.TimeoutExpired:
        return None, "Timeout", -1
    except Exception as e:
        return None, str(e), -1


def check_and_warn(name, extra_install=""):
    avail = find_tool(name)
    if not avail:
        install_hint = extra_install or f"Install with: apt install {name}  or  pip install {name}"
        warning(f"{name} not found. {install_hint}")
    return avail


def nmap_scan(target, ports=""):
    if not find_tool("nmap"):
        return None
    args = ["nmap", "-sV", "-sC", "--version-intensity", "2", "-T4", "--open"]
    if ports:
        args += ["-p", ports]
    args.append(target)
    info("Running nmap -sV -sC for service/version detection...")
    stdout, stderr, code = run_tool(args, timeout=300)
    if code != 0:
        return None
    results = []
    current_port = None
    for line in stdout.split("\n"):
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
        if m:
            port = int(m.group(1))
            service = m.group(2)
            version = m.group(3).strip()
            results.append((port, "open", service, version))
    return results if results else None


def dnsrecon_enum(target):
    if not find_tool("dnsrecon"):
        return None
    args = ["dnsrecon", "-d", target, "-t", "std"]
    info("Running dnsrecon for comprehensive DNS enumeration...")
    stdout, stderr, code = run_tool(args, timeout=120)
    if code != 0:
        return None
    records = {}
    for line in stdout.split("\n"):
        m = re.match(r"^(\w+)\s+(\S+)\s+(\S.*)", line)
        if m:
            rtype = m.group(1)
            rval = f"{m.group(2)} {m.group(3)}".strip()
            records.setdefault(rtype, []).append(rval)
        m = re.match(r"\[([A-Z]+)\]\s+(\S+)", line)
        if m:
            rtype = m.group(1)
            rval = m.group(2)
            records.setdefault(rtype, []).append(rval)
    return records if records else None


def dig_all_records(target):
    if not find_tool("dig"):
        return None
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR", "NAPTR", "DS", "DNSKEY"]
    all_records = {}
    for rtype in record_types:
        args = ["dig", "+short", target, rtype]
        stdout, stderr, code = run_tool(args, timeout=30)
        if code == 0 and stdout.strip():
            all_records[rtype] = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    return all_records if all_records else None


def dig_zone_transfer(target, ns_server):
    if not find_tool("dig"):
        return None
    args = ["dig", "axfr", target, f"@{ns_server}"]
    stdout, stderr, code = run_tool(args, timeout=30)
    if code == 0 and "Transfer failed" not in stdout and "refused" not in stderr.lower():
        records = [line.strip() for line in stdout.split("\n") if line.strip() and not line.startswith(";") and not line.startswith(";") and line.strip()]
        return records if records else None
    return None


def sublist3r_enum(target):
    if not find_tool("sublist3r"):
        return None
    args = ["sublist3r", "-d", target]
    info("Running sublist3r for subdomain enumeration...")
    stdout, stderr, code = run_tool(args, timeout=120)
    if code != 0:
        return None
    subdomains = []
    for line in stdout.split("\n"):
        line = line.strip()
        if line.endswith(f".{target}") or (line.startswith("http") and target in line):
            from urllib.parse import urlparse
            try:
                sub = urlparse(line).netloc or line
                if sub not in subdomains:
                    subdomains.append(sub)
            except:
                pass
        elif line and "." in line and target in line:
            if line not in subdomains:
                subdomains.append(line)
    return subdomains if subdomains else None


def amass_enum(target):
    if not find_tool("amass"):
        return None
    args = ["amass", "enum", "-passive", "-d", target, "-o", "-"]
    info("Running amass (passive) for subdomain enumeration...")
    stdout, stderr, code = run_tool(args, timeout=180)
    if code != 0:
        return None
    subdomains = [line.strip() for line in stdout.split("\n") if line.strip() and target in line]
    return subdomains if subdomains else None


def assetfinder_enum(target):
    if not find_tool("assetfinder"):
        return None
    args = ["assetfinder", "--subs-only", target]
    info("Running assetfinder for subdomain enumeration...")
    stdout, stderr, code = run_tool(args, timeout=60)
    if code != 0:
        return None
    subdomains = [line.strip() for line in stdout.split("\n") if line.strip() and target in line]
    return subdomains if subdomains else None


def ffuf_dir_bust(target, wordlist, extensions=""):
    if not find_tool("ffuf"):
        return None
    args = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-t", "50", "-ac", "-o", "-", "-of", "json"]
    if extensions:
        args += ["-e", extensions]
    info("Running ffuf for fast directory enumeration...")
    stdout, stderr, code = run_tool(args, timeout=300)
    if code != 0 and code != 1:
        return None
    results = []
    try:
        data = json.loads(stdout)
        for result_entry in data.get("results", []):
            url = result_entry.get("url", "")
            status = result_entry.get("status", 0)
            size = result_entry.get("length", 0)
            path = url.replace(target, "").lstrip("/")
            results.append((status, path, size, url))
    except (json.JSONDecodeError, Exception):
        for line in stdout.split("\n"):
            m = re.match(r"^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)", line)
            if m:
                url = m.group(1)
                status = int(m.group(2))
                size = int(m.group(3))
                path = url.replace(target, "").lstrip("/")
                results.append((status, path, size, url))
    return results if results else None


def gobuster_dir_bust(target, wordlist, extensions=""):
    if not find_tool("gobuster"):
        return None
    args = ["gobuster", "dir", "-u", target, "-w", wordlist, "-t", "50", "-q"]
    if extensions:
        args += ["-x", extensions]
    info("Running gobuster for directory enumeration...")
    stdout, stderr, code = run_tool(args, timeout=300)
    if code != 0:
        stdout = stdout or ""
        stderr = stderr or ""
        combined = stdout + stderr
    results = []
    combined = (stdout or "") + (stderr or "")
    for line in combined.split("\n"):
        m = re.match(r"^/(\S+)\s+\(Status:\s*(\d+)\).*\(Size:\s*(\d+)\)", line)
        if m:
            path = m.group(1)
            status = int(m.group(2))
            size = int(m.group(3))
            results.append((status, path, size, f"{target}/{path}"))
    return results if results else None


def whatweb_detect(target):
    if not find_tool("whatweb"):
        return None
    args = ["whatweb", "-a", "3", "--color=never", target]
    info("Running whatweb for technology detection...")
    stdout, stderr, code = run_tool(args, timeout=60)
    if code != 0 or not stdout:
        return None
    results = []
    for match in re.finditer(r"(\w[\w\s]+?)\[([^\]]+)\]", stdout):
        tech = match.group(1).strip()
        version_info = match.group(2).strip()
        results.append((tech, version_info))
    if not results:
        parts = stdout.strip().split(", ")
        for part in parts[1:]:
            m = re.match(r"(\w[\w\s]*?)\[([^\]]+)\]", part.strip())
            if m:
                results.append((m.group(1).strip(), m.group(2).strip()))
    return results if results else None


def wafw00f_detect(target):
    if not find_tool("wafw00f"):
        return None
    args = ["wafw00f", target, "-a"]
    info("Running wafw00f for WAF detection...")
    stdout, stderr, code = run_tool(args, timeout=60)
    if code != 0:
        return None
    wafs = []
    in_results = False
    for line in stdout.split("\n"):
        if "Number of WAFs detected" in line:
            in_results = True
            continue
        if in_results and line.strip() and "Back to normal" not in line:
            m = re.match(r"^\+\s+(.+?)(?:\s*\[(.+)\])?$", line)
            if m:
                waf_name = m.group(1).strip()
                details = m.group(2) or ""
                wafs.append((waf_name, details))
    if not wafs:
        for line in stdout.split("\n"):
            if "detected" in line.lower():
                m = re.match(r"^.+\s+detected\s+(.+?)(?:\s*-\s*(.+))?$", line)
                if m:
                    wafs.append((m.group(1).strip(), m.group(2).strip() if m.group(2) else ""))
    return wafs if wafs else None


def openssl_check(host, port=443):
    if not find_tool("openssl"):
        return None
    args = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief"]
    info(f"Running openssl s_client for TLS analysis on {host}:{port}...")
    stdout, stderr, code = run_tool(args, timeout=30)
    if code != 0:
        return None
    info_data = {}
    for line in (stdout or "").split("\n"):
        line = line.strip()
        if "://" in line:
            parts = line.split("://", 1)
            if len(parts) == 2:
                info_data["protocol"] = parts[1].strip()
        elif "Cipher" in line or "cipher" in line:
            m = re.search(r"(\S+-\S+-?\S*)", line)
            if m:
                info_data["cipher"] = m.group(1)
        elif "Subject" in line or "subject" in line:
            m = re.search(r"subject=(.*)", line, re.I)
            if m:
                info_data["subject"] = m.group(1).strip()
        elif "Issuer" in line or "issuer" in line:
            m = re.search(r"issuer=(.*)", line, re.I)
            if m:
                info_data["issuer"] = m.group(1).strip()
    return info_data if info_data else None


def openssl_test_versions(host, port=443):
    if not find_tool("openssl"):
        return None, None
    results = {}
    tls_methods = [
        ("tls1_3", ["s_client", "-connect", f"{host}:{port}", "-tls1_3", "-brief"]),
        ("tls1_2", ["s_client", "-connect", f"{host}:{port}", "-tls1_2", "-brief"]),
        ("tls1_1", ["s_client", "-connect", f"{host}:{port}", "-tls1_1", "-brief"]),
        ("tls1",   ["s_client", "-connect", f"{host}:{port}", "-tls1", "-brief"]),
        ("ssl3",   ["s_client", "-connect", f"{host}:{port}", "-ssl3", "-brief"]),
    ]
    supported = []
    unsupported = []
    for name, args in tls_methods:
        args_full = ["openssl"] + args
        stdout, stderr, code = run_tool(args_full, timeout=15)
        if code == 0 or (stdout and "CONNECTED" in stdout):
            supported.append(name.upper())
        else:
            unsupported.append(name.upper())
    return supported, unsupported


def gospider_crawl(target, depth=2):
    if not find_tool("gospider"):
        return None
    args = ["gospider", "-s", target, "-d", str(depth), "-t", "2", "-c", "30", "-o", "-o", "-q"]
    info("Running gospider for enhanced crawling...")
    stdout, stderr, code = run_tool(args, timeout=180)
    if code != 0 and stdout is None:
        return None
    urls = set()
    for line in (stdout or "").split("\n"):
        for part in line.split():
            if part.startswith("http://") or part.startswith("https://"):
                urls.add(part.rstrip(')";,'))
    return sorted(urls) if urls else None


def hakrawler_crawl(target, depth=2):
    if not find_tool("hakrawler"):
        return None
    args = ["hakrawler", "-d", str(depth), "-subs", "-insecure"]
    info("Running hakrawler for enhanced crawling...")
    result = subprocess.run(
        ["echo", target],
        capture_output=True, text=True, timeout=5
    )
    try:
        proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=target, timeout=120)
        if proc.returncode != 0:
            return None
        urls = set()
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.add(line.rstrip(')";,'))
        return sorted(urls) if urls else None
    except:
        return None


def subjs_scan(target):
    if not find_tool("subjs"):
        return None
    args = ["subjs", "-i", target]
    info("Running subjs for JavaScript file discovery...")
    stdout, stderr, code = run_tool(args, timeout=60)
    if code != 0:
        return None
    urls = [line.strip() for line in (stdout or "").split("\n") if line.strip().startswith("http")]
    return urls if urls else None


def linkfinder_scan(target):
    if not find_tool("linkfinder") and not find_tool("LinkFinder"):
        return None
    tool = "linkfinder" if find_tool("linkfinder") else "LinkFinder"
    args = [tool, "-i", target, "-o", "cli"]
    info(f"Running {tool} for endpoint discovery in JavaScript...")
    stdout, stderr, code = run_tool(args, timeout=60)
    if code != 0 or not stdout:
        return None
    endpoints = set()
    for line in stdout.split("\n"):
        m = re.search(r"(https?://[^\s\"'<>]+)", line)
        if m:
            endpoints.add(m.group(1).rstrip(",;)\"'"))
        m = re.search(r"(\"[^\"]*\")", line)
        if m:
            val = m.group(1).strip("\"")
            if val.startswith("/") and len(val) > 3:
                endpoints.add(val)
    return sorted(endpoints) if endpoints else None


def host_lookup(domain):
    if not find_tool("host"):
        return None
    args = ["host", domain]
    stdout, stderr, code = run_tool(args, timeout=15)
    if code != 0:
        return None
    records = {}
    for line in (stdout or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        if "has address" in line:
            records.setdefault("A", []).append(line.split("has address")[-1].strip())
        elif "has IPv6 address" in line:
            records.setdefault("AAAA", []).append(line.split("has IPv6 address")[-1].strip())
        elif "mail is handled" in line:
            records.setdefault("MX", []).append(line.split("mail is handled")[-1].strip())
        elif "name server" in line:
            records.setdefault("NS", []).append(line.split("name server")[-1].strip())
        elif "descriptive text" in line:
            records.setdefault("TXT", []).append(line.split("descriptive text")[-1].strip())
    return records if records else None


def host_ptr(ip):
    if not find_tool("host"):
        return None
    args = ["host", ip]
    stdout, stderr, code = run_tool(args, timeout=15)
    if code == 0 and "domain name pointer" in (stdout or ""):
        m = re.search(r"domain name pointer\s+(\S+)", stdout)
        if m:
            return m.group(1).rstrip(".")
    return None
