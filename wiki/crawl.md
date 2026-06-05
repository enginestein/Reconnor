# Web Crawler

Recursively crawls a website to enumerate URLs and site structure.

```
python3 main.py crawl https://example.com --depth 3 --max-urls 200
```

**Options:**
- `--depth` — Max crawl depth (default: 2)
- `--max-urls` — Max URLs to collect (default: 100)
- `--timeout` — HTTP timeout (default: 10)
