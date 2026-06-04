# Ollama AI Integration

8 tools support AI-assisted analysis via local LLMs through [Ollama](https://ollama.ai).

## Setup

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (start with a small one)
ollama pull llama3.2

# Verify it's running
ollama list
```

## Usage

Add `--ollama-model <model>` to any supported tool:

```bash
python3 main.py admin https://example.com --ollama-model llama3.2
python3 main.py dir-bust https://example.com --ollama-model llama3.2
python3 main.py fuzz https://example.com/page?id=1 --ollama-model llama3.2
python3 main.py sqli https://example.com/page?id=1 --ollama-model llama3.2
python3 main.py xss https://example.com/page?q=test --ollama-model llama3.2
python3 main.py forms https://example.com/login --ollama-model llama3.2
python3 main.py js https://example.com --ollama-model llama3.2
python3 main.py openredirect https://example.com --ollama-model llama3.2
```

## What Each Tool Does with AI

| Tool | How Ollama Helps |
|------|-----------------|
| **admin** | Generates custom admin panel paths based on detected CMS/tech stack |
| **dir-bust** | Generates framework-specific directory and file paths |
| **fuzz** | Generates parameter-specific fuzz payloads tailored to the tech stack |
| **sqli** | Generates WAF bypass SQLi payloads specific to the detected DBMS |
| **xss** | Generates CSP-aware XSS payloads for the specific context |
| **forms** | Analyzes form HTML for security issues missed by static rules |
| **js** | Finds secrets, API endpoints, and internal routes beyond regex patterns |
| **openredirect** | Generates creative redirect bypass payloads |

The AI phase runs BEFORE the standard hardcoded tests, so AI-generated payloads are tested alongside the built-in ones.
