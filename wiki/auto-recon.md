# Auto Recon

Autonomous recon orchestration with AI-driven decision making and chained tool execution.

```
python3 main.py auto-recon example.com --ext --light
python3 main.py auto-recon example.com --use-ai --llm-provider openai
```

**Options:**
- `--use-ai` — Enable AI-driven decision making
- `--llm-provider` — LLM provider (ollama, openai, anthropic, gemini)
- `--llm-model` — LLM model name
- `--light` — Run lighter tool chain (skip crawl, js, forms)
- `--threads` — Max threads per tool (default: 50)
- `--timeout` — HTTP timeout (default: 10)
- `--ext` — Use external tools where available
- `--nmap` — Use nmap for port scan
