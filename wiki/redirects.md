# Redirect Chain Tracker

Traces the full HTTP redirect chain from initial request to final destination.

```
python3 main.py redirects example.com
python3 main.py redirects https://example.com/page
python3 main.py redirects example.com --ollama-model llama3.2
```

**Options:**
- `--ollama-model` — Use Ollama for AI analysis of the redirect chain

**What it detects:**
- Redirect loops
- HTTPS → HTTP downgrades
- Cookie leakage across redirects
- Broken chains (4xx/5xx)
- Open redirect patterns

**Output:** Per-hop table with status codes and URLs, plus security analysis section.
