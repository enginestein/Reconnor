# Credential Sprayer

Credential sprayer: password spraying with anti-lockout detection and cooldown.

```
python3 main.py cred-spray https://example.com/login --username admin --passwords Password1,Welcome1
python3 main.py cred-spray https://example.com/login --user-file users.txt --pass-file pass.txt
```

**Options:**
- `--url` — Target login URL
- `--target` — Target (alias for --url)
- `--username` — Single username
- `--usernames` — Comma-separated usernames
- `--user-file` — File with usernames
- `--password` — Single password
- `--passwords` — Password list
- `--pass-file` — File with passwords
- `--delay` — Delay between attempts (default: 2)
- `--lockout-threshold` — Lockout threshold (default: 5)
- `--max-attempts` — Passwords per user (default: 3)
- `--field-user` — Username field name (default: username)
- `--field-pass` — Password field name (default: password)
- `--fail-str` — Login failure string (default: invalid)
- `--timeout` — HTTP timeout (default: 15)
