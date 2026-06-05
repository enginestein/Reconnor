# WebSocket Tester

WebSocket security tester: origin bypass, message fuzzing, DoS resistance.

```
python3 main.py ws wss://example.com/ws --fuzz --dos
```

**Options:**
- `--url` — WebSocket URL (ws:// or wss://)
- `--target` — Target (alias for --url)
- `--origin` — Custom origin header to test
- `--message` — Custom message to send
- `--fuzz` — Fuzz WebSocket messages
- `--dos` — Test DoS resistance
- `--timeout` — Connection timeout (default: 15)
