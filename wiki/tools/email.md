# Email Extractor

Extracts email addresses from web pages using regex patterns.

```
python3 main.py email https://example.com
python3 main.py email https://example.com --crawl --depth 2 --max 50
```

**Options:**
- `--crawl, -c` — Crawl linked pages
- `--depth` — Crawl depth (default: 1)
- `--max` — Max pages (default: 20)
