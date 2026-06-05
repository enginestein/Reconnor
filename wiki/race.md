# Race Condition Tester

Race condition tester: concurrent request racing for discount, OTP, rate-limit bypass.

```
python3 main.py race https://example.com/coupon --threads 50
```

**Options:**
- `--url` — Target URL
- `--target` — Target (alias for --url)
- `--method` — HTTP method
- `--data` — Request body
- `--headers` — Custom headers as JSON
- `--threads` — Number of concurrent requests (default: 50)
- `--param` — Parameter to vary
- `--delay` — Delay between requests
- `--scenario` — Test scenario (coupon/otp/rate, default: generic)
- `--timeout` — HTTP timeout (default: 15)
