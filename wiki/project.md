# Project Database

Project database: SQLite-backed target/project management with scan comparison.

```
python3 main.py project --cmd init --name engagement1 --target example.com
python3 main.py project --cmd save --project engagement1 --tool port-scan --file results.json
python3 main.py project --cmd compare --compare 1,2
```

**Options:**
- `--cmd` (required) — Command: init/list/save/runs/show/compare/delete
- `--name` — Project or run name
- `--project` — Project name
- `--target` — Target description
- `--tool-name` — Tool name
- `--file` — Result JSON file to save
- `--runs` — List runs
- `--compare` — Compare run IDs (comma-sep)
- `--timeout` — Operation timeout (default: 5)
