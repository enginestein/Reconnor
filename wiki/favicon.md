# Favicon Hash Calculator

Downloads a site's favicon and computes its mmh3 hash for Shodan-based device identification.

```
python3 main.py favicon example.com
python3 main.py favicon https://example.com/custom/path
```

**Output:** mmh3 hash value and ready-to-use Shodan query.

**How it works:** Fetches `/favicon.ico`, parses `<link rel="icon">` from HTML, computes mmh3 hash. Use the hash in Shodan: `http.favicon.hash:<hash>`

**Dependency:** Install `mmh3` for accurate Shodan-compatible hashing: `pip install mmh3`
