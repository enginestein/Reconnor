# JavaScript Scraper

Extracts API endpoints, routes, secrets, and hardcoded strings from JavaScript files.

```
python3 main.py js https://example.com
python3 main.py js https://example.com --threads 30
```

**Options:**
- `--threads` — Max threads (default: 20)
- `--ollama-model` — Ollama model for AI-powered endpoint/secret discovery beyond regex
