# Cloud Metadata Scanner

Cloud metadata exposure scanner for AWS, Azure, GCP, Alibaba, DigitalOcean, OpenStack.

```
python3 main.py cloud-meta --check-all
```

**Options:**
- `--target` — Target (unused, scans from current host)
- `--provider` — Single provider to check (AWS/GCP/Azure/etc)
- `--check-all` — Check all providers
- `--timeout` — HTTP timeout (default: 5)
