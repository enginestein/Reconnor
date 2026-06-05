# Google Dork Generator

Generates Google search queries across 12 categories (admin panels, logs, config files, databases, etc.).

```
python3 main.py dork
python3 main.py dork --domain example.com
python3 main.py dork --category "Login"
```

**Options:**
- `--domain, -d` — Scope queries to domain
- `--category, -c` — Filter by category
