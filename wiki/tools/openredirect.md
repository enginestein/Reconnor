# Open Redirect Checker

Tests URL parameters for open redirect vulnerabilities (validation bypass, JS/DOM discovery, CRLF, param pollution).

```
python3 main.py openredirect https://example.com/page?url=http://evil.com
python3 main.py openredirect https://example.com
```

**Options:**
- `--timeout` — HTTP timeout (default: 10)
- `--ollama-model` — Ollama model for AI-generated redirect bypass payloads
