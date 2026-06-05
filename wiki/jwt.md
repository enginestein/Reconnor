# JWT Toolkit

JWT analysis and attack toolkit: decode, crack, algorithm confusion, KID injection.

```
python3 main.py jwt --token eyJhbGciOiJIUzI1NiIs...
python3 main.py jwt --token eyJ... --crack --wordlist rockyou.txt
```

**Options:**
- `--token` — JWT token to analyze
- `--crack` — Attempt to crack the JWT secret
- `--wordlist, -w` — Wordlist for JWT cracking
- `--alg` — Algorithm confusion test (e.g., HS256)
- `--target` — Target server URL for sending modified tokens
- `--kid-knject` — KID injection payload
- `--jwki-url` — JWK confusion target URL
