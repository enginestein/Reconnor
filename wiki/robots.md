# Robots.txt & Sitemap Analyzer

Analyzes robots.txt and sitemap.xml for recon opportunities and hidden resources.

```
python3 main.py robots example.com
python3 main.py robots https://example.com
python3 main.py robots example.com --ollama-model llama3.2
```

**Options:**
- `--ollama-model` — Use Ollama to analyze disallowed paths and sitemap URLs

**What it finds:**
- All disallowed paths (potential recon targets)
- Sitemap URLs (hidden/forgotten pages)
- Crawl delays and host directives
- Sensitive paths not blocked by robots.txt
- AI identifies what's likely behind disallowed paths

**Example:**
```
python3 main.py robots example.com --ollama-model llama3.2
```
