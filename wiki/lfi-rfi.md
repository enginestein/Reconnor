# LFI/RFI Scanner

Local File Inclusion and Remote File Inclusion vulnerability scanner. Tests URL parameters with 50+ path traversal payloads including PHP wrappers, null byte injection, /proc/self/environ, log poisoning, and remote URL inclusion.

```
python3 main.py lfi-rfi https://example.com/page?file=test
python3 main.py lfi-rfi https://example.com --params file,page,path --ollama-model llama3.2
python3 main.py lfi-rfi https://example.com/page --method POST --data "file=test"
```

**Options:**
- `--params` -- Comma-separated parameter names to test (auto-detects from URL if omitted)
- `--method` -- HTTP method (GET/POST, default: GET)
- `--data` -- POST data for parameter injection
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--threads` -- Max concurrent threads (default: 20)
- `--ollama-model` -- Ollama model for AI-generated LFI/RFI payloads

**How it works:** Injects path traversal sequences (../../../etc/passwd), PHP filter wrappers (php://filter/convert.base64-encode/resource=index.php), data:// and expect:// wrappers, remote URL inclusion payloads, and /proc/self/environ into URL parameters. Detects successful inclusion by matching response body against known system file signatures.
