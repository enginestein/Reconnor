# API Fuzzer

Advanced REST/GraphQL API fuzzer: header injection, param pollution, rate limit testing.

```
python3 main.py api-fuzz https://api.example.com --inject-headers --rate-limit
```

**Options:**
- `--url` — Target API URL
- `--target` — Target (alias for --url)
- `--method` — HTTP method (GET/POST)
- `--data` — Request body data
- `--headers` — Custom headers as JSON
- `--params` — Custom parameters
- `--inject-headers` — Test header injection
- `--pollute` — Test parameter pollution
- `--rate-limit` — Test rate limiting
- `--timeout` — HTTP timeout (default: 15)
- `--threads` — Max threads (default: 20)
