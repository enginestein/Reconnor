# GitHub OSINT

Queries GitHub for user profiles, repository info, or code search.

```
python3 main.py github john --mode user
python3 main.py github tensorflow --mode repo
python3 main.py github "api key" --mode search
```

**Options:**
- `--mode` — Query mode: `user` (default), `repo`, or `search`
