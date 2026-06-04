# Shodan Search

Search Shodan.io for devices, services, and open ports.

```
python3 main.py shodan example.com
python3 main.py shodan 8.8.8.8
python3 main.py shodan --query "apache 2.4.49 country:US"
python3 main.py shodan --query "http.favicon.hash:-1775126190" --limit 50
python3 main.py shodan example.com --ollama-model llama3.2
```

**Options:**
- `--query, -q` — Shodan search query (instead of domain/IP lookup)
- `--limit, -l` — Max search results (default: 20)
- `--ollama-model` — Use Ollama for AI analysis of results

**API Key:** Requires a Shodan API key. Set via `SHODAN_API_KEY` env var or save to `~/.shodan/api_key`. Get a free key at https://account.shodan.io/

**Two modes:**
1. **Host lookup** (`shodan example.com`) — Shows open ports, services, hostnames, ASN, OS, vulnerabilities
2. **Search** (`shodan --query "..."`) — Searches Shodan database and shows port/service distribution, top organizations
