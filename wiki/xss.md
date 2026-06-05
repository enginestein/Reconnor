# XSS Scanner

Tests URL parameters and forms with 150+ XSS payloads (context-aware, polyglots, DOM, stored, mXSS, CSP analysis).

```
python3 main.py xss https://example.com/page?q=test
```

**Options:**
- `--timeout` — HTTP timeout (default: 10)
- `--ollama-model` — Ollama model for AI-generated XSS payloads (CSP-aware)
