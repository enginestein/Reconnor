# DNS Enumeration

Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA). Optionally attempts zone transfer.

```
python3 main.py dns example.com
python3 main.py dns example.com --zone-transfer
```

**Options:**
- `--zone-transfer, -z` — Attempt DNS zone transfer
