# Password Strength Analyzer

Password strength analyzer: entropy, patterns, crack time estimation.

```
python3 main.py pass-analyze --password MyP@ssw0rd!
```

**Options:**
- `--password` — Single password to analyze
- `--passwords` — Comma-separated password list
- `--min-len` — Minimum password length (default: 8)
- `--no-common` — Skip common password check
- `--verbose` — Verbose output
