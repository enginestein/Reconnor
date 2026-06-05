# SSRF Scanner

Blind and reflected SSRF detection with out-of-band verification and cloud metadata probing.

```
python3 main.py ssrf --url "http://example.com/page?url=SSRF"
python3 main.py ssrf --url "http://example.com/page?url=SSRF" --blind
```

**Options:**
- `--url` — Target URL with injection point (use =SSRF as placeholder)
- `--urls` — Comma-separated list of target URLs
- `--method` — HTTP method (GET/POST)
- `--data` — POST data (use $param as placeholder)
- `--headers` — Custom headers as JSON
- `--timeout` — HTTP timeout (default: 10)
- `--threads` — Max threads (default: 10)
- `--blind` — Enable blind SSRF (out-of-band) testing
- `--collaborator` — Custom collaborator URL (default: interactsh)
