# SSTI Scanner

SSTI scanner supporting Jinja2, Twig, Freemarker, Velocity, Jade, ERB, Tornado, Mako, Smarty.

```
python3 main.py ssti https://example.com/page?name=test
python3 main.py ssti https://example.com/page?name=test --rce
```

**Options:**
- `--url` — Target URL
- `--target` — Target (alias for --url)
- `--params` — Comma-separated parameter names
- `--method` — HTTP method (default: GET)
- `--data` — POST data
- `--rce` — Attempt RCE exploitation
- `--file-read` — File to read via SSTI
- `--timeout` — HTTP timeout (default: 15)
- `--threads` — Max threads (default: 10)
