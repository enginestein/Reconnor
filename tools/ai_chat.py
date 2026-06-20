import json
import os
import re
import subprocess
import sys
import threading
import time
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

TOOLS_WITH_POSITIONAL_TARGET = {
    "admin", "asn", "auto-recon", "breach", "c2-hunt", "certsearch", "cloud",
    "cors", "crawl", "cve", "deep-search", "dir-bust", "dns", "email",
    "email-finder", "email-recon", "favicon", "forms", "fuzz", "geoip",
    "github", "headers", "httpmethods", "js", "links", "mac-address",
    "malware-hunt", "metadata", "openredirect", "pastewatch", "phish-hunt",
    "phone-info", "phone-social", "port-scan", "reddit-osint", "redirects",
    "reverseip", "robots", "shodan", "smtp", "sociallinks", "social-recon",
    "sqli", "ssl", "subdomain", "tech", "telegram-osint", "tor-check",
    "username", "waf", "wayback", "whois", "xss",
}


def _build_tools_help():
    from tools import HELP_DESCRIPTIONS
    lines = []
    for cat_name, cat_tools in CATEGORIES:
        lines.append(f"\n  [{cat_name}]")
        for name in cat_tools:
            desc = HELP_DESCRIPTIONS.get(name, "")
            lines.append(f"    {name}: {desc}")
    return "\n".join(lines)


SYSTEM_PROMPT_TPL = """You are Reconnor AI, a cybersecurity research partner built into the Reconnor hacking suite.

You help with recon, OSINT, vulnerability scanning, and security testing by running tools and analyzing ACTUAL results.

=== TOOL EXECUTION ===
To run a tool, output TOOL: on its own line:
TOOL: tool-name target

Most tools just need the target (URL/domain/IP) as a positional argument. Do NOT add made-up arguments like --method, --path, --url-param, --data, etc.

For tools that need specific flags, use only these known patterns:
  --target X  (for most tools that need a target)
  --url X     (for ssrf, ssti, race, ws, xxe, brute, cred-spray, default-creds, graphql, smuggle)
  --domain X  (for dork, takeover)
  --token X   (for jwt)
  --hash X    (for hash-id)
  --password X (for pass-analyze)
  --input X   (for report)

=== CRITICAL RULES ===
1. NEVER describe findings from a tool before it has run. Only say what you plan to do.
2. After a tool runs, analyze the ACTUAL results. If the tool errors, report the error honestly.
3. Output at most ONE TOOL command per response. After the tool runs and results are analyzed, the system returns control to the user. You must wait for the user to respond before running another tool.
4. Do NOT invent arguments. Only use the argument patterns listed above.
5. If a tool fails, try a simpler invocation: just TOOL: tool-name target.
6. If you have a plan with multiple steps, explain the full plan in text, then execute the first step with ONE TOOL command. The conversation history will remember the remaining steps.
7. After all planned steps are done or when the user asks for a review, provide a comprehensive conclusion summarizing ALL findings, their risk levels, and actionable recommendations.

=== AVAILABLE TOOLS ===
{TOOLS_PLACEHOLDER}
"""


def _get_system_prompt():
    return SYSTEM_PROMPT_TPL.replace("{TOOLS_PLACEHOLDER}", _build_tools_help())


class Spinner:
    def __init__(self):
        self._spin_chars = "|/-\\"
        self._idx = 0
        self._running = False
        self._thread = None

    def _spin(self):
        while self._running:
            sys.stdout.write(f"\r  \033[93m[{self._spin_chars[self._idx % len(self._spin_chars)]}]\033[0m thinking...")
            sys.stdout.flush()
            self._idx += 1
            time.sleep(0.12)

    def start(self):
        if utils.output.QUIET:
            return
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()


class AIChat:
    description = "Interactive AI chat that runs recon/scanning tools autonomously"

    @staticmethod
    def run(prompt="", model="", provider="", cli=False, **kwargs):
        llm = LLMHelper(provider=provider, model=model)
        os.makedirs(os.path.expanduser("~/.reconnor"), exist_ok=True)

        if not cli:
            try:
                from tools.ai_chat_tui import AIChatTUIApp
            except ImportError:
                error("Textual is required for TUI mode. Install: pip install textual")
                return {"error": "textual not installed"}

            ai = AIChat()
            app = AIChatTUIApp(llm=llm, ai_instance=ai, prompt=prompt)
            app.run()
            return {"result": "tui session ended"}

        if not llm.available:
            provider_name = provider or os.environ.get("RECONNOR_LLM", "ollama")
            error(f"No LLM backend available for '{provider_name}'")
            error("Set RECONNOR_LLM (ollama/openai/anthropic/gemini) and required API keys")
            return {"error": f"No LLM backend available for '{provider_name}'"}

        ai = AIChat()
        if HAS_READLINE and os.path.exists(HISTORY_FILE):
            try:
                readline.read_history_file(HISTORY_FILE)
            except:
                pass

        if prompt:
            ai.conversation.append({"role": "user", "content": prompt})
            print()
            ai._converse(llm)

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

    def _interactive_loop(self, llm):
        print()
        print(f"  \033[96mReconnor AI Chat\033[0m")
        print(f"  Type \033[93mexit\033[0m to end  |  \033[93mhelp\033[0m for commands")
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
                print("  \033[92mConversation cleared\033[0m")
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
                print(f"  \033[92mSaved to {path}\033[0m")
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

    def _call_llm(self, llm):
        spinner = Spinner()
        spinner.start()
        response = llm.chat(
            self._build_context(),
            system=_get_system_prompt(),
            temperature=0.3,
            max_tokens=2048,
        )
        spinner.stop()
        return response

    def _converse(self, llm):
        response = self._call_llm(llm)

        if not response or not response.strip():
            error("AI returned no response")
            self.conversation.append({"role": "user", "content": "Please continue with your analysis."})
            return self._converse(llm)

        text_before, tool_commands = self._extract_tools(response)
        self.conversation.append({"role": "assistant", "content": response})

        if text_before:
            self._show_response(text_before)

        if not tool_commands:
            return

        cmd = tool_commands[0]
        result_data = self._execute_tool(cmd)
        if result_data is None:
            return

        if result_data.get("error", "").startswith("Unknown tool:"):
            unknown_tool = result_data["error"].replace("Unknown tool: ", "")
            tools_list = ", ".join(
                t for cat in CATEGORIES for t in cat[1]
            )
            msg = (
                f"You tried to run '{unknown_tool}' which does not exist. "
                f"Here are the available tools: {tools_list}. "
                "Pick one from this list and try again."
            )
            self.conversation.append({"role": "user", "content": msg})
            self._show_response(msg)
            return

        summary = json.dumps(result_data, indent=2, default=str)[:2000]

        self.conversation.append({
            "role": "user",
            "content": f"Tool executed: {cmd}\n\nResults:\n{summary}\n\nAnalyze these results. What are the key findings? Then ask the user what they want to do next.",
        })

        next_response = self._call_llm(llm)
        if next_response:
            self.conversation.append({"role": "assistant", "content": next_response})
            self._show_response(next_response)

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

    def _show_response(self, text):
        if utils.output.QUIET or not text:
            return
        for line in text.strip().split("\n"):
            print(f"  {line}")
        print()

    def _normalize_tool_args(self, tool_name, tool_args):
        args = list(tool_args)
        new_args = []
        skip_next = False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if a == "--target" and i + 1 < len(args):
                if tool_name in TOOLS_WITH_POSITIONAL_TARGET:
                    new_args.insert(0, args[i + 1])
                else:
                    new_args.append(a)
                    new_args.append(args[i + 1])
                skip_next = True
            else:
                new_args.append(a)
        return new_args

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

        tool_args = self._normalize_tool_args(tool_name, tool_args)

        if "--json" not in tool_args:
            tool_args.append("--json")

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py = os.path.join(project_root, "main.py")
        cmd = [sys.executable, main_py, tool_name] + tool_args

        print(f"  \033[96m[{tool_name}]\033[0m running...")
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
                    if stripped and not stripped.startswith("{"):
                        print(f"  \033[90m{stripped}\033[0m")
            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            stdout_chunks = []
            for line in iter(proc.stdout.readline, ""):
                stdout_chunks.append(line)

            proc.wait()
            stderr_thread.join(timeout=3)

            stdout = "".join(stdout_chunks).strip()

            if proc.returncode != 0:
                stderr_text = "".join(stderr_lines)
                if "unrecognized arguments" in stderr_text:
                    bad_args = self._extract_unrecognized_args(stderr_text)
                    if bad_args:
                        remaining = [a for a in tool_args if a not in bad_args]
                        for b in bad_args:
                            try:
                                idx = remaining.index(b)
                                remaining.pop(idx)
                                if idx < len(remaining):
                                    remaining.pop(idx)
                            except ValueError:
                                pass
                        if remaining != tool_args:
                            return self._execute_tool_raw(tool_name, remaining)
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
                return {"raw_output": stdout[:500]}

        except FileNotFoundError:
            error(f"main.py not found at {main_py}")
            return {"error": "main.py not found"}
        except Exception as e:
            error(f"Error: {e}")
            return {"error": str(e)}

    def _extract_unrecognized_args(self, stderr_text):
        m = re.search(r"unrecognized arguments:\s*(.+)", stderr_text)
        if not m:
            return []
        parts = m.group(1).strip().split()
        result = []
        i = 0
        while i < len(parts):
            p = parts[i].strip("'\"")
            if p.startswith("-"):
                result.append(p)
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    result.append(parts[i + 1].strip("'\""))
                    i += 2
                else:
                    i += 1
            else:
                i += 1
        return result

    def _execute_tool_raw(self, tool_name, tool_args):
        if "--json" not in tool_args:
            tool_args.append("--json")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py = os.path.join(project_root, "main.py")
        cmd = [sys.executable, main_py, tool_name] + tool_args
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                return {"error": f"exit code {proc.returncode}"}
            if not stdout:
                return {"error": "no output"}
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"raw_output": stdout[:500]}
        except Exception as e:
            return {"error": str(e)}
