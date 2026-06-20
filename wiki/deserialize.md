# Insecure Deserialization Scanner

Insecure deserialization vulnerability scanner that tests PHP serialized objects, Python pickle, Java serialized streams, Ruby YAML, and .NET PowerShell objects.

```
python3 main.py deserialize https://example.com/api/upload
python3 main.py deserialize https://example.com --param data --ollama-model llama3.2
```

**Options:**
- `--param` -- Parameter name containing serialized data (default: data)
- `--method` -- HTTP method (GET/POST, default: POST)
- `--data` -- Raw POST data override
- `--content-type` -- Custom Content-Type header value
- `--timeout` -- HTTP timeout in seconds (default: 10)
- `--ollama-model` -- Ollama model for AI-generated deserialization payloads

**How it works:** Sends crafted serialized objects across multiple content types (application/x-www-form-urlencoded, application/json, application/xml, application/php-serialized, application/java-serialized-object). Detects deserialization vulnerabilities by monitoring for PHP fatal errors, Python pickling errors, Java exceptions, and command execution indicators in responses.
