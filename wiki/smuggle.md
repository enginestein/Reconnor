# HTTP Request Smuggler

HTTP request smuggler: CL.TE, TE.CL, TE.TE detection and exploitation.

```
python3 main.py smuggle example.com --port 80
```

**Options:**
- `--target` — Target hostname
- `--url` — Target URL (alias for --target)
- `--port` — Target port (default: 80)
- `--tls` — Use TLS
- `--timeout` — Socket timeout (default: 10)
