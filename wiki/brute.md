# Login Brute Forcer

HTTP form/basic/digest authentication brute forcer with auto field detection.

```
python3 main.py brute --url http://example.com/login --user admin
python3 main.py brute --url http://example.com/wp-login.php --user-file users.txt --pass-file pass.txt
```

**Options:**
- `--url` — Target URL for login page
- `--username` — Single username
- `--usernames` — Comma-separated username list
- `--password` — Single password
- `--passwords` — Comma-separated password list
- `--user-file` — File with usernames
- `--pass-file` — File with passwords
- `--method` — Auth method (auto/form/basic)
- `--field-user` — Username form field name
- `--field-pass` — Password form field name
- `--auth-type` — Force auth type (form/basic)
- `--success-str` — String indicating login success
- `--fail-str` — String indicating login failure
- `--threads` — Max threads (default: 10)
- `--timeout` — HTTP timeout (default: 15)
- `--delay` — Delay between attempts (default: 0)
