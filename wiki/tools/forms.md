# Form Security Analyzer

Analyzes HTML forms for security issues: password fields over HTTP, missing CSRF tokens, autocomplete enabled, credential leaks, API key exposure.

```
python3 main.py forms https://example.com/login
python3 main.py forms https://example.com/login --ollama-model llama3.2
```

**Options:**
- `--ollama-model` — Ollama model for AI-powered form security analysis
