# Subdomain Finder

Brute-forces subdomains using a built-in wordlist of 1000+ common subdomains.

```
python3 main.py subdomain example.com
python3 main.py subdomain example.com -w /path/to/wordlist.txt --threads 100
```

**Options:**
- `--wordlist, -w` — Custom subdomain wordlist
- `--threads` — Max threads (default: 50)
