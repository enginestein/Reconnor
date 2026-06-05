# Subdomain Takeover Checker

Subdomain takeover detection across AWS, Azure, GitHub, Heroku, Netlify, and 20+ services.

```
python3 main.py takeover --domain sub.example.com
python3 main.py takeover --domains sub1.example.com,sub2.example.com
```

**Options:**
- `--domain` — Single domain to check
- `--domains` — Comma-separated list of domains
- `--threads` — Max threads (default: 20)
- `--timeout` — HTTP timeout (default: 10)
