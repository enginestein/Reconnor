import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime

from utils.llm_helper import LLMHelper
from utils.output import section, info, success, warning, error, result
import utils.output

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

HISTORY_FILE = os.path.expanduser("~/.reconnor/ai_history.txt")

CATEGORIES = [
    ("Recon / OSINT", ["port-scan", "subdomain", "dns", "whois", "certsearch", "reverseip", "geoip", "asn", "mac-address", "favicon", "wayback"]),
    ("Web Analysis", ["headers", "ssl", "tech", "waf", "crawl", "links", "js", "forms", "robots", "redirects", "httpmethods", "cors"]),
    ("Vulnerability", ["sqli", "xss", "ssti", "xxe", "openredirect", "fuzz", "graphql", "api-fuzz", "smuggle", "ws", "race", "ssrf", "jwt"]),
    ("Network / Infra", ["net-scan", "snmp", "smb", "nfs", "ldap", "rpc", "smtp"]),
    ("Auth / Credentials", ["cred-spray", "default-creds", "brute", "pass-analyze", "hash-id"]),
    ("Cloud / K8s", ["aws-enum", "k8s", "container", "cloud-meta", "cloud", "takeover"]),
    ("OSINT / Search", ["shodan", "github", "dork", "cve", "breach", "username", "email", "email-finder", "email-recon", "phone-info", "phone-social", "telegram-osint", "reddit-osint", "social-recon", "sociallinks", "deep-search", "pastewatch", "malware-hunt", "c2-hunt", "phish-hunt"]),
    ("Utilities", ["report", "project", "auto-recon"]),
]

def _build_tools_help():
    from tools import HELP_DESCRIPTIONS
    lines = []
    for cat_name, cat_tools in CATEGORIES:
        lines.append(f"\n  [{cat_name}]")
        for name in cat_tools:
            desc = HELP_DESCRIPTIONS.get(name, "")
            lines.append(f"    {name}: {desc}")
    return "\n".join(lines)

SYSTEM_PROMPT_TPL = """You are Reconnor AI — an autonomous cybersecurity assistant built into the Reconnor hacking suite.

Your purpose: help users with reconnaissance, OSINT, vulnerability scanning, and security testing by running tools and analyzing results in real time. You PLAN, EXECUTE, and ANALYZE — like a senior penetration tester.

=== TOOL EXECUTION ===
When you want to run a tool, output a TOOL command on its own line:

TOOL: tool-name --arg1 value1 --arg2 value2

You can include text before and after TOOL commands. Multiple TOOL commands are OK — they will be run in sequence. If no tool is needed, just respond as a helpful assistant.

Examples:
  TOOL: port-scan example.com --ports 22,80,443
  TOOL: subdomain example.com
  TOOL: whois example.com
  TOOL: hash-id --hash 5d41402abc4b2a76b9719d911017c592
  TOOL: tech https://example.com
  TOOL: dns example.com --recursive

=== AVAILABLE TOOLS ===
{TOOLS_PLACEHOLDER}

=== GUIDELINES ===
1. Understand the user's goal first, then plan which tools to run and in what order
2. Run tools ONE AT A TIME. After each tool, analyze results before deciding the next step
3. ALWAYS explain your reasoning before running a tool ("Let me check...")
4. After getting results, summarize key findings and suggest what to do next
5. Chain tools logically: recon (whois/dns) -> port scan -> web tech -> vulnerability scan
6. For URL targets, include http:// or https:// prefix
7. Be professional, concise, and security-focused
8. If the user asks a question that doesn't need a tool, just answer it directly
9. CRITICAL: When a tool returns errors or empty results, adapt your plan — don't keep running failing tools
10. After 3-4 tool runs, ask the user if they want to continue or change direction
"""

def _get_system_prompt():
    return SYSTEM_PROMPT_TPL.replace("{TOOLS_PLACEHOLDER}", _build_tools_help())


class AIChat:
    description = "Interactive AI chat that runs recon/scanning tools autonomously"

    @staticmethod
    def run(prompt="", model="", provider="", **kwargs):
        llm = LLMHelper(provider=provider, model=model)
        if not llm.available:
            provider_name = provider or os.environ.get("RECONNOR_LLM", "ollama")
            error(f"No LLM backend available for '{provider_name}'")
            error("Set RECONNOR_LLM (ollama/openai/anthropic/gemini) and required API keys")
            return {"error": f"No LLM backend available for '{provider_name}'"}

        ai = AIChat()
        os.makedirs(os.path.expanduser("~/.reconnor"), exist_ok=True)

        if HAS_READLINE and os.path.exists(HISTORY_FILE):
            try:
                readline.read_history_file(HISTORY_FILE)
            except:
                pass

        if prompt:
            result_text = ai._process_single(prompt, llm)
            return {"result": result_text}
        else:
            ai._interactive_loop(llm)
            return {"result": "interactive session ended"}

    def __init__(self):
        self.conversation = []
        self.max_history = 30

    def _build_context(self):
        messages = self.conversation[-self.max_history:]
        return "\n\n".join(
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in messages
        )

    def _process_single(self, prompt, llm):
        self.conversation.append({"role": "user", "content": prompt})
        self._converse(llm)
        # Return the last assistant response
        for msg in reversed(self.conversation):
            if msg["role"] == "assistant":
                text = msg["content"]
                # Strip tool commands from the response text
                lines = [l for l in text.split("\n") if not re.match(r"^TOOL:\s", l.strip(), re.IGNORECASE)]
                return "\n".join(lines).strip()
        return None

    def _interactive_loop(self, llm):
        print()
        print(f"  {'=' * 56}")
        print(f"  \033[96mReconnor AI Chat\033[0m — autonomous security testing assistant")
        print(f"  Type \033[93mexit\033[0m or \033[93mquit\033[0m to end  |  \033[93mhelp\033[0m for commands")
        print(f"  {'=' * 56}")
        print()

        while True:
            try:
                user_input = input("  \033[94mYou:\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not user_input:
                continue

            cmd = user_input.lower()
            if cmd in ("exit", "quit"):
                break

            if cmd == "help":
                print("  \033[93mCommands:\033[0m")
                print("    exit / quit    End session")
                print("    clear          Clear conversation history")
                print("    history        Show conversation summary")
                print("    save           Save conversation to JSON file")
                print("    model          Show current LLM provider/model")
                continue

            if cmd == "clear":
                self.conversation = []
                print("  \033[92m[+] Conversation cleared\033[0m")
                continue

            if cmd == "history":
                for i, m in enumerate(self.conversation):
                    role = "\033[94mUser\033[0m" if m["role"] == "user" else "\033[92mAI\033[0m"
                    content = m["content"][:120].replace("\n", " ")
                    print(f"  [{i}] {role}: {content}...")
                continue

            if cmd == "save":
                path = os.path.expanduser(
                    f"~/.reconnor/chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                with open(path, "w") as f:
                    json.dump(self.conversation, f, indent=2)
                print(f"  \033[92m[+] Saved to {path}\033[0m")
                continue

            if cmd == "model":
                print(f"  Provider: {llm.provider}")
                print(f"  Model: {llm.model}")
                print(f"  Available: {llm.available}")
                continue

            if HAS_READLINE:
                try:
                    readline.add_history(user_input)
                    readline.write_history_file(HISTORY_FILE)
                except:
                    pass

            self.conversation.append({"role": "user", "content": user_input})
            self._converse(llm)

    def _converse(self, llm):
        context = self._build_context()

        self._show_thinking()
        response = llm.chat(context, system=_get_system_prompt(), temperature=0.3, max_tokens=2048)

        if not response:
            error("AI returned no response")
            return None

        self._process_response(response, llm, max_depth=6)
        return response

    def _process_response(self, response, llm, max_depth=6):
        if max_depth <= 0:
            return

        text_before, tool_commands = self._extract_tools(response)
        self.conversation.append({"role": "assistant", "content": response})

        if text_before:
            self._show_response(text_before)

        for cmd in tool_commands:
            result_data = self._execute_tool(cmd)
            if result_data is None:
                continue

            summary = json.dumps(result_data, indent=2, default=str)[:3000]
            followup = (
                f"Tool executed: {cmd}\n\nResults:\n{summary}\n\n"
                f"Analyze these results. What are the key findings? What should I do next?"
            )
            self.conversation.append({"role": "user", "content": followup})

            context = self._build_context()
            self._show_thinking()
            next_response = llm.chat(
                context, system=_get_system_prompt(), temperature=0.3, max_tokens=2048
            )

            if next_response:
                self._process_response(next_response, llm, max_depth - 1)

    def _extract_tools(self, response):
        lines = response.split("\n")
        tool_cmds = []
        text_lines = []
        for line in lines:
            stripped = line.strip()
            if re.match(r"^TOOL:\s", stripped, re.IGNORECASE):
                tool_cmds.append(stripped)
            else:
                text_lines.append(line)
        return "\n".join(text_lines).strip(), tool_cmds

    def _show_thinking(self):
        if utils.output.QUIET:
            return
        print(f"  \033[93m{'=' * 56}\033[0m")
        print(f"  \033[93m  🤔  Thinking...\033[0m")
        print(f"  \033[93m{'=' * 56}\033[0m")
        sys.stdout.flush()

    def _show_response(self, text):
        if utils.output.QUIET or not text:
            return
        print(f"\n  \033[92m💬\033[0m {text}\n")

    def _execute_tool(self, cmd_line):
        cmd_line = cmd_line.strip()
        match = re.match(r"^TOOL:\s*(.*)", cmd_line, re.IGNORECASE)
        if match:
            cmd_line = match.group(1).strip()

        parts = cmd_line.split()
        if not parts:
            return None

        tool_name = parts[0]
        tool_args = parts[1:]

        from tools import TOOLS
        if tool_name not in TOOLS:
            error(f"Unknown tool: {tool_name}")
            return {"error": f"Unknown tool: {tool_name}"}

        if "--json" not in tool_args:
            tool_args.append("--json")

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py = os.path.join(project_root, "main.py")
        cmd = [sys.executable, main_py, tool_name] + tool_args

        if not utils.output.QUIET:
            print(f"\n  \033[96m🔧  Running {tool_name}...\033[0m")
            sys.stdout.flush()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            stderr_lines = []
            def _read_stderr():
                for line in iter(proc.stderr.readline, ""):
                    stderr_lines.append(line)
                    stripped = line.strip()
                    if not utils.output.QUIET and stripped and not stripped.startswith("{"):
                        print(f"    \033[90m{stripped}\033[0m")
            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            stdout_chunks = []
            for line in iter(proc.stdout.readline, ""):
                stdout_chunks.append(line)

            proc.wait()
            stderr_thread.join(timeout=3)

            stdout = "".join(stdout_chunks).strip()

            if proc.returncode != 0:
                error(f"Tool exited with code {proc.returncode}")
                return {"error": f"exit code {proc.returncode}"}

            if not stdout:
                warning("No output from tool")
                return {"error": "no output"}

            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                json_match = re.search(r"\{.*\}", stdout, re.DOTALL)
                if json_match:
                    try:
                        return json.loads(json_match.group())
                    except:
                        pass
                warning(f"Non-JSON output from {tool_name}")
                return {"raw_output": stdout[:500]}

        except FileNotFoundError:
            error(f"main.py not found at {main_py}")
            return {"error": "main.py not found"}
        except Exception as e:
            error(f"Error: {e}")
            return {"error": str(e)}
