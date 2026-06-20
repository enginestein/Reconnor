# Host Header Injection Scanner

Host header injection scanner that tests for cache poisoning, password reset poisoning, SSRF via host, and virtual host routing bypass vulnerabilities.

```
python3 main.py host-header-injection https://example.com
python3 main.py host-header-injection https://example.com --ollama-model llama3.2
```

**Options:**
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--ollama-model` -- Ollama model for AI-generated host header payloads

**How it works:** Sends requests with 15+ modified Host header values (evil.com, localhost, 127.0.0.1, etc.) and X-Forwarded-Host/X-Forwarded-Server/X-Host/X-Original-URL/Forwarded header variants. Checks if injected values are reflected in the response body, Location headers (password reset poisoning), or if cache headers are present alongside reflected content (cache poisoning).
