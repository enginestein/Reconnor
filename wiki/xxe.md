# XXE Scanner

XXE scanner: file read, SSRF, blind exfiltration, 9 DOCTYPE variants including XInclude and SVG.

```
python3 main.py xxe https://example.com/xml --file-read /etc/passwd
```

**Options:**
- `--url` — Target URL
- `--target` — Target (alias for --url)
- `--data` — Raw XML data
- `--param` — Parameter name holding XML
- `--content-type` — Content-Type header value
- `--file-read` — File to read via XXE
- `--collaborator` — OOB collaborator URL
- `--timeout` — HTTP timeout (default: 15)
