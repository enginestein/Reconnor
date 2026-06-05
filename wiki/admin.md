# Admin Panel Finder

Scans 250+ common admin panel paths and checks for login indicators using CMS-specific detection and fuzzy matching.

```
python3 main.py admin https://example.com
```

**Options:**
- `--timeout` — HTTP timeout (default: 10)
- `--threads` — Max threads (default: 20)
- `--ollama-model` — Ollama model name (e.g., `llama3.2`, `mistral`) for AI-generated custom admin paths based on detected technology
