# Port Scanner

Scans TCP ports on a target host with banner grabbing.

```
python3 main.py port-scan example.com
python3 main.py port-scan 192.168.1.1 --ports 1-1000
python3 main.py port-scan example.com --ports 22,80,443,3306 --timeout 3 --threads 200
```

**Options:**
- `--ports, -p` — Port range (e.g., `1-1000`, `22,80,443`)
- `--timeout` — Connection timeout in seconds (default: 2)
- `--threads` — Max concurrent threads (default: 100)

**How it works:** Opens raw TCP sockets in parallel to check if ports are open. Grabs service banners when possible.
