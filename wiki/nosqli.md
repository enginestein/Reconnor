# NoSQL Injection Scanner

NoSQL injection vulnerability scanner for MongoDB and other NoSQL databases. Tests URL parameters and JSON bodies with $ne, $gt, $regex, $where operators.

```
python3 main.py nosqli https://example.com/login?username=admin
python3 main.py nosqli https://example.com/api/login --method POST --data '{"username":"admin","password":"test"}'
python3 main.py nosqli https://example.com/search?q=test --ollama-model llama3.2
```

**Options:**
- `--params` -- Comma-separated parameter names to test (auto-detects from URL if omitted)
- `--method` -- HTTP method (GET/POST, default: GET)
- `--data` -- POST data with parameter placeholder
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--threads` -- Max concurrent threads (default: 20)
- `--ollama-model` -- Ollama model for AI-generated NoSQL payloads

**How it works:** Tests query string parameters with NoSQL operators ($ne, $gt, $regex, $exists, $where) and sends crafted JSON objects with $ne/$gt filters in POST bodies. Detects authentication bypass by analyzing response content for success indicators.
