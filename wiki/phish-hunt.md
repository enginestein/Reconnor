# Phish Hunt

Phishing infrastructure hunter. Searches URLScan.io for phishing pages, monitors Certificate Transparency logs for suspicious domains, discovers phishing kits and templates, and analyzes indicators of phishing infrastructure.

```
python3 main.py phish-hunt example.com
python3 main.py phish-hunt example.com --deep
python3 main.py phish-hunt "paypal" --deep
```

**Options:**
- `--timeout` — HTTP timeout (default: 15)
- `--deep`, `-d` — Deep scan: includes google dorking and credential leak checks

**Phases:**
1. **URLScan.io** — Searches for pages matching the target, flags malicious verdicts and brand spoofing
2. **Certificate Transparency** — Finds lookalike domains with suspicious certs (typosquatting, homograph attacks)
3. **Phishing Kit Discovery** — Searches for known phishing kit references and templates targeting your brand
4. **Indicator Analysis** — Detects phishing keywords, suspicious TLDs, brand impersonation, leet-speak
5. **Deep dorking** — Google dork queries to find exposed credential harvesters and login pages
6. **Credential leak scan** — Checks paste sites and URLScan for exposed credential files

**Risk tiers:** CRITICAL, HIGH, MEDIUM, LOW — based on URLScan verdicts, suspicious certs, kit references, indicators, and credential leaks.
