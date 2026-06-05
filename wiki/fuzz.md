# URL Fuzzer

Tests URL parameters with fuzz payloads including XSS, SQLi, path traversal, and more (12+ categories).

```
python3 main.py fuzz https://example.com/page?id=1
python3 main.py fuzz https://example.com/page --params id,page,user
```

**Options:**
- `--params` — Custom parameters to fuzz (comma-separated)
- `--threads` — Max threads (default: 20)
- `--ollama-model` — Ollama model for AI-generated fuzz payloads
