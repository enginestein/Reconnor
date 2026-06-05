# AI Chat

Interactive AI chat that runs recon/scanning tools autonomously using natural language.

```
python3 main.py ai-chat "scan example.com for open ports"
python3 main.py ai-chat
```

**Options:**
- `prompt` — Question or task (omit for interactive mode)
- `--model` — LLM model override
- `--provider` — LLM provider override (ollama/openai/anthropic/gemini)
