# Default Credential Checker

Default credential checker with 500+ known device/service default credentials.

```
python3 main.py default-creds https://example.com --category router
python3 main.py default-creds https://example.com --service tomcat
```

**Options:**
- `--url` — Target URL
- `--target` — Target (alias for --url)
- `--service` — Filter by service name
- `--category` — Filter by category (router/firewall/web/db/cms/iot/service)
- `--timeout` — HTTP timeout (default: 10)
