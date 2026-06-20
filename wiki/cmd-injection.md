# Command Injection Scanner

Command injection vulnerability scanner with time-based and blind detection. Tests URL parameters with 40+ OS command injection payloads.

```
python3 main.py cmd-injection https://example.com/ping?host=test
python3 main.py cmd-injection https://example.com --params ip,host,domain --ollama-model llama3.2
python3 main.py cmd-injection https://example.com/traceroute --method POST --data "target=test"
```

**Options:**
- `--params` -- Comma-separated parameter names to test (auto-detects from URL if omitted)
- `--method` -- HTTP method (GET/POST, default: GET)
- `--data` -- POST data for parameter injection
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--threads` -- Max concurrent threads (default: 20)
- `--ollama-model` -- Ollama model for AI-generated command injection payloads

**How it works:** Injects command injection payloads including semicolon (; id), pipe (| whoami), subshell ($(id)), backtick (`id`), and newline (%0A id) injection. Uses time-based detection by measuring response delays from sleep/ping payloads and output-based verification by checking responses for uid=, root:, and other command output signatures.
