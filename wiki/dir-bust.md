# Directory Bruteforcer

Tests 1000+ common web paths. Optionally appends common extensions (.php, .asp, .aspx, .jsp, .do, .html).

```
python3 main.py dir-bust https://example.com
python3 main.py dir-bust https://example.com --extensions
python3 main.py dir-bust https://example.com -w /path/to/wordlist.txt
```

**Options:**
- `--wordlist, -w` — Custom path wordlist
- `--extensions, -e` — Try common extensions
- `--threads` — Max threads (default: 30)
- `--timeout` — HTTP timeout (default: 10)
- `--ollama-model` — Ollama model for AI-generated tech-specific paths
