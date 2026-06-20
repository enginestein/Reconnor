# Wordlist Generator

Custom wordlist generator that scrapes target websites to extract words, URLs, paths, form fields, CSS classes, and JS endpoints. Applies leetspeak mutations and case variants. Optionally uses AI for target-specific word suggestions.

```
python3 main.py wordlist https://example.com --size large --mutation
python3 main.py wordlist https://example.com --out custom.txt --depth 3
python3 main.py wordlist https://example.com --min-len 4 --max-len 20 --ollama-model llama3.2
```

**Options:**
- `--depth` -- Crawl depth for scraping (default: 2)
- `--output, -o` -- Output wordlist file path
- `--size` -- Wordlist size: small (200 common words), medium (500), large (1000+) (default: medium)
- `--min-len` -- Minimum word length (default: 3)
- `--max-len` -- Maximum word length (default: 30)
- `--mutation` -- Enable leetspeak (a->4, e->3, etc.) and case mutations
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--ollama-model` -- Ollama model for AI-generated word suggestions

**How it works:** Recursively crawls the target website extracting words from visible text, URL paths, form field names, HTML IDs/CSS classes, meta keywords, HTML comments, script src attributes, and JavaScript. Merges with a curated common wordlist based on the selected size. Optionally applies leetspeak mutations, capitalization variants, and AI-generated target-specific entries.
