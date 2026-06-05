# Link Extractor

Extracts all links from a web page and optionally checks their HTTP status.

```
python3 main.py links https://example.com
python3 main.py links https://example.com --check
```

**Options:**
- `--check` — Check link health (HTTP status)
- `--threads` — Max threads (default: 20)
