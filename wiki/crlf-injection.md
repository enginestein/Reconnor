# CRLF Injection Scanner

CRLF (HTTP Response Splitting) injection scanner. Tests URL parameters and headers for CRLF injection vulnerabilities that can lead to cache poisoning, XSS, and header injection.

```
python3 main.py crlf-injection https://example.com/page?file=test
python3 main.py crlf-injection https://example.com --params file,url,next --ollama-model llama3.2
```

**Options:**
- `--params` -- Comma-separated parameter names to test (auto-detects from URL if omitted)
- `--method` -- HTTP method (GET/POST, default: GET)
- `--data` -- POST data
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--ollama-model` -- Ollama model for AI-generated CRLF payloads

**How it works:** Injects %0d%0a, %0a, %0d, double-encoded (%250d%250a), and unicode (%u000d%u000a) CRLF sequences into URL parameters and Host headers. Detects injected Set-Cookie headers, Location redirects, Content-Length manipulation, and injected HTML/JavaScript in response bodies.
