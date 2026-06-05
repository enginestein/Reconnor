# GraphQL Scanner

GraphQL security scanner: introspection, batching attacks, query depth, auth bypass.

```
python3 main.py graphql https://api.example.com/graphql
python3 main.py graphql https://api.example.com/graphql --auth-bypass
```

**Options:**
- `--url` — GraphQL endpoint URL
- `--target` — Target domain (auto-discovers endpoint)
- `--query` — Custom GraphQL query
- `--no-introspection` — Skip introspection
- `--no-batch` — Skip batch testing
- `--no-depth` — Skip depth testing
- `--auth-bypass` — Test auth bypass
- `--timeout` — HTTP timeout (default: 15)
