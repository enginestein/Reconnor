# Report Generator

Generate HTML/JSON/text pentest reports from JSON output files.

```
python3 main.py report --input results.json --format html
python3 main.py report --input scan1.json,scan2.json --output report.html --title "Pentest Report"
```

**Options:**
- `--input` (required) — Comma-separated JSON result files
- `--format` — Report format (html/json/txt, default: html)
- `--title` — Report title
- `--author` — Report author
- `--target` — Target description
- `--domain` — Target domain
- `--url` — Target URL
