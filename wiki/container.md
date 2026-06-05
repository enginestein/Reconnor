# Container Security Scanner

Container security scanner: Docker API, breakout tests, image vulnerability check.

```
python3 main.py container 192.168.1.100 --breakout
```

**Options:**
- `--target` — Target hostname/IP
- `--host` — Host alias
- `--port` — Docker API port
- `--socket` — Docker socket path
- `--breakout` — Test container breakout
- `--images` — Check container images
- `--timeout` — Socket timeout (default: 10)
