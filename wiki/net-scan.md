# Network Scanner

Network scanner: ARP discovery, ping sweep, OS fingerprinting, port scanning.

```
python3 main.py net-scan --subnet 192.168.1.0/24 --ping --os-detect
```

**Options:**
- `--target` — Single target host
- `--subnet` — CIDR subnet (e.g., 192.168.1.0/24)
- `--ports` — Ports to scan (default: 22,80,443,3306,3389,8080,8443)
- `--no-ping` — Skip ping sweep
- `--arp` — Show ARP table
- `--os-detect` — Attempt OS fingerprinting
- `--threads` — Max threads (default: 100)
- `--timeout` — Socket timeout (default: 5)
