# Certificate Transparency Search

Queries crt.sh and CertSpotter for SSL certificate records to discover subdomains.

```
python3 main.py certsearch example.com
python3 main.py certsearch example.com --all
```

**Options:**
- `--all, -a` — Show all entries (not just unique)
