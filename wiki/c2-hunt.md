# C2 Hunt

C2 (Command & Control) infrastructure reconnaissance. Checks blocklists, fingerprints SSL certificates for C2 patterns, matches known C2 panel paths, and queries ThreatFox for C2 intelligence.

```
python3 main.py c2-hunt example.com
python3 main.py c2-hunt 185.130.5.173 --port 8080
python3 main.py c2-hunt example.com --check-paths
```

**Options:**
- `--port` — Port for SSL fingerprinting (default: 443)
- `--timeout` — HTTP timeout (default: 15)
- `--check-paths` — Brute force common C2 panel paths

**SSL fingerprints checked:**
- Self-signed certs (common for C2)
- Unusually long (>800 day) or short (<30 day) validity
- CN mismatch with domain (evasion pattern)
- LetsEncrypt with mismatched subject

**C2 patterns detected:**
- Known C2 panel paths (/gate.php, /otsystem, /jquery-*.php patterns)
- C2 framework indicators (CobaltStrike, Metasploit, Mythic)
- Malware loader endpoints, botnet APIs, DNS-over-HTTPS tunnels

**API setup:** Set `ABUSE_API_KEY` env var for ThreatFox integration.
