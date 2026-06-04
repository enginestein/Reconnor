# SQL Injection Scanner

Tests URL parameters with 200+ SQL injection payloads (error-based, boolean, time-based, stacked queries, WAF bypass, second-order).

```
python3 main.py sqli https://example.com/page?id=1
```

**Options:**
- `--timeout` — HTTP timeout (default: 10)
- `--ollama-model` — Ollama model for AI-generated SQLi payloads (adapts to detected DBMS)
