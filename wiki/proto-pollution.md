# Server-Side Prototype Pollution Scanner

Server-side prototype pollution vulnerability scanner for Node.js applications. Tests for __proto__ and constructor.prototype injection via JSON bodies, query strings, and custom headers.

```
python3 main.py proto-pollution https://example.com/api/user
python3 main.py proto-pollution https://example.com --method POST --ollama-model llama3.2
```

**Options:**
- `--params` -- Comma-separated parameter names to test
- `--method` -- HTTP method (GET/POST, default: GET)
- `--data` -- POST data
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--ollama-model` -- Ollama model for AI-generated prototype pollution payloads

**How it works:** Sends JSON objects with __proto__ and constructor.prototype properties in POST bodies, query string parameters with __proto__.isAdmin=true patterns, and custom X-Prototype-Pollution headers. Detects pollution by checking response bodies for injected property values and comparing response sizes against baselines.
