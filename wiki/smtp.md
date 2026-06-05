# SMTP Enumeration

Resolves MX records, connects to SMTP servers, enumerates supported commands, and checks for open relay.

```
python3 main.py smtp example.com
python3 main.py smtp example.com --port 587
```

**Options:**
- `--port` — SMTP port (default: 25)
- `--timeout` — Connection timeout (default: 10)
