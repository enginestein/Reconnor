import json
import os
import re
import sys
import subprocess
import threading
from datetime import datetime

from rich.markup import escape

from textual import on
from textual.app import App
from textual.containers import (
    Horizontal,
    ScrollableContainer,
    Vertical,
)
from textual.widgets import (
    Button,
    Collapsible,
    Footer,
    Input,
    Static,
)

from tools import HELP_DESCRIPTIONS, TOOLS
from utils.llm_helper import LLMHelper

HISTORY_FILE = os.path.expanduser("~/.reconnor/ai_history.txt")

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

CATEGORIES_LIST = [
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
    lines = []
    for cat_name, cat_tools in CATEGORIES_LIST:
        lines.append(f"\n  [{cat_name}]")
        for name in cat_tools:
            desc = HELP_DESCRIPTIONS.get(name, "")
            lines.append(f"    {name}: {desc}")
    return "\n".join(lines)


def _get_system_prompt():
    return SYSTEM_PROMPT_TPL.replace("{TOOLS_PLACEHOLDER}", _build_tools_help())


class FindingsDB:
    def __init__(self):
        self.findings = []
        self.tasks = []
        self.raw_results = {}
        self.current_target = ""

    def add_finding(self, tool, summary, severity="info"):
        self.findings.append({
            "tool": tool,
            "summary": summary,
            "severity": severity,
            "time": datetime.now().strftime("%H:%M:%S"),
        })

    def add_task(self, tool_name, status="done"):
        if tool_name not in [t["name"] for t in self.tasks]:
            self.tasks.append({"name": tool_name, "status": status})

    def add_raw_result(self, tool_name, result_data):
        self.raw_results[tool_name] = json.dumps(result_data, indent=2, default=str)

    def clear(self):
        self.findings.clear()
        self.tasks.clear()
        self.raw_results.clear()


class Sidebar(Vertical):
    def __init__(self, db: FindingsDB, **kwargs):
        super().__init__(**kwargs)
        self.db = db

    def compose(self):
        yield Static("[bold]Key Findings[/]", id="findings-title")
        yield ScrollableContainer(id="findings-container")
        yield Static("")
        yield Static("[bold]Tasks Ran[/]", id="tasks-title")
        yield ScrollableContainer(id="tasks-container")
        yield Static("")
        with Collapsible(title="Raw Results", collapsed=True):
            yield ScrollableContainer(id="raw-container")
        with Collapsible(title="Available Scans", collapsed=False):
            yield ScrollableContainer(id="scans-container")

    def on_mount(self):
        self._populate_scans()
        self._update_all()

    def _populate_scans(self):
        try:
            container = self.query_one("#scans-container")
            for cat_name, cat_tools in CATEGORIES_LIST:
                container.mount(Static(f"[bold]{cat_name}[/]"))
                for name in cat_tools:
                    container.mount(Static(f"  {name}"))
        except Exception:
            pass

    def _update_all(self):
        self._render_findings()
        self._render_tasks()
        self._render_raw()

    def _render_findings(self):
        try:
            container = self.query_one("#findings-container")
            container.remove_children()
            if not self.db.findings:
                container.mount(Static("  No findings yet"))
                return
            for f in self.db.findings:
                sev_colors = {"critical": "red", "high": "yellow", "medium": "magenta", "info": "green"}
                color = sev_colors.get(f["severity"], "white")
                safe_tool = escape(f["tool"])
                safe_summary = escape(f["summary"])
                text = f"  [{color}]●[/] {safe_tool}: {safe_summary}"
                container.mount(Static(text))
        except Exception:
            pass

    def _render_tasks(self):
        try:
            container = self.query_one("#tasks-container")
            container.remove_children()
            if not self.db.tasks:
                container.mount(Static("  No tasks ran yet"))
                return
            for t in self.db.tasks:
                icon = "✓" if t["status"] == "done" else "○"
                safe_name = escape(t["name"])
                container.mount(Static(f"  {icon} [bold]{safe_name}[/]"))
        except Exception:
            pass

    def _render_raw(self):
        try:
            container = self.query_one("#raw-container")
            container.remove_children()
            if not self.db.raw_results:
                container.mount(Static("  No raw results"))
                return
            for tool_name, result_str in self.db.raw_results.items():
                safe_name = escape(tool_name)
                container.mount(Static(f"[bold]{safe_name}[/]"))
                container.mount(Static(result_str[:800], markup=False))
        except Exception:
            pass


class ChatMessage(Static):
    pass


class AIChatTUIApp(App):
    TITLE = "Reconnor AI Chat"
    CSS = """
    Screen {
        layout: horizontal;
    }

    #sidebar {
        width: 32%;
        height: 100%;
        dock: left;
        border: solid $primary;
        padding: 0 1;
        background: $surface;
    }

    #findings-title, #tasks-title {
        text-style: bold;
        color: $accent;
        padding: 0 0;
        margin: 1 0 0 0;
    }

    #findings-container {
        height: auto;
        max-height: 10;
        overflow-y: auto;
    }

    #tasks-container {
        height: auto;
        max-height: 8;
        overflow-y: auto;
    }

    #raw-container {
        height: auto;
        max-height: 12;
        overflow-y: auto;
    }

    #scans-container {
        height: auto;
        max-height: 12;
        overflow-y: auto;
    }

    #main-panel {
        width: 68%;
        height: 100%;
        layout: vertical;
    }

    #chat-container {
        height: 1fr;
        border: solid $primary;
        margin: 0 0 1 0;
        padding: 1;
        overflow-y: auto;
    }

    #loading-indicator {
        height: 1;
        text-style: bold;
        color: $accent;
        margin: 0 0 0 1;
    }

    #input-row {
        height: 3;
        layout: horizontal;
        margin: 0 0 1 0;
    }

    #chat-input {
        width: 1fr;
    }

    #send-btn {
        width: 10;
        margin: 0 0 0 1;
    }

    Collapsible {
        margin: 0 0;
    }

    Collapsible > Static {
        padding: 0 1;
    }

    Static {
        margin: 0 0;
    }

    .user-msg {
        color: $text;
        background: $primary-background;
        padding: 0 1;
        margin: 1 0;
    }

    .ai-msg {
        color: $text;
        background: $surface;
        padding: 0 1;
        margin: 1 0;
    }

    .tool-msg {
        color: $accent;
        margin: 0 0 0 2;
    }

    .result-msg {
        color: $text-muted;
        margin: 0 0 0 2;
    }

    .error-msg {
        color: $error;
        margin: 0 0 0 2;
    }
    """

    def __init__(self, llm, ai_instance, prompt=""):
        super().__init__()
        self.llm = llm
        self.ai = ai_instance
        self.initial_prompt = prompt
        self.db = FindingsDB()
        self.conversation = []
        self.max_history = 50
        self._running_tool = False
        self._spinner_timer = None
        self._spinner_idx = 0

    def compose(self):
        with Vertical(id="sidebar"):
            yield Sidebar(self.db, id="sidebar-content")
        with Vertical(id="main-panel"):
            yield ScrollableContainer(id="chat-container")
            yield Static("", id="loading-indicator")
            with Horizontal(id="input-row"):
                yield Input(placeholder="Type your message...", id="chat-input")
                yield Button("Send", id="send-btn", variant="primary")
        yield Footer()

    def on_mount(self):
        self.query_one("#chat-input").focus()
        if not self.llm.available:
            provider_name = self.llm.provider or "ollama"
            self._add_chat_message("error",
                f"No LLM backend available for '{provider_name}'. "
                f"Set RECONNOR_LLM (ollama/openai/anthropic/gemini) and required API keys. "
                f"The sidebar still shows available scans while you configure your LLM.")
        elif self.initial_prompt:
            self._handle_user_input(self.initial_prompt)

    @on(Input.Submitted, "#chat-input")
    def on_input_submitted(self, event):
        self._handle_user_input(event.value)

    @on(Button.Pressed, "#send-btn")
    def on_send(self):
        input_widget = self.query_one("#chat-input")
        if input_widget.value.strip():
            self._handle_user_input(input_widget.value)

    def _add_chat_message(self, role, content, msg_class="ai-msg"):
        chat = self.query_one("#chat-container")
        timestamp = datetime.now().strftime("%H:%M")
        prefix = "You" if role == "user" else "AI"
        safe = escape(content)
        if role == "tool":
            label = Static(f"  [{timestamp}] [bold]{safe}[/]", classes="tool-msg")
        elif role == "error":
            label = Static(f"  [{timestamp}] {safe}", classes="error-msg")
        elif role == "result":
            label = Static(f"  [{timestamp}] {safe}", classes="result-msg")
        elif role == "system":
            label = Static(f"  [{timestamp}] {safe}", classes="tool-msg")
        else:
            label = Static(f"[{timestamp}] [bold]{prefix}:[/] {safe}", classes=msg_class)
        chat.mount(label)
        chat.scroll_end(animate=False)

    def _handle_user_input(self, text):
        text = text.strip()
        if not text:
            return

        input_widget = self.query_one("#chat-input")
        input_widget.value = ""
        input_widget.focus()

        cmd = text.lower()
        if cmd in ("exit", "quit"):
            self.exit()
            return
        if cmd == "clear":
            chat = self.query_one("#chat-container")
            chat.remove_children()
            self.conversation = []
            self.db.clear()
            self.call_after_refresh(self._sidebar_update)
            return

        self._add_chat_message("user", text, "user-msg")
        self.conversation.append({"role": "user", "content": text})
        self._converse()
        self.call_after_refresh(self._sidebar_update)

    def _build_context(self):
        messages = self.conversation[-self.max_history:]
        return "\n\n".join(
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in messages
        )

    def _call_llm(self):
        response = self.llm.chat(
            self._build_context(),
            system=_get_system_prompt(),
            temperature=0.3,
            max_tokens=2048,
        )
        return response

    def _converse(self):
        if self._running_tool:
            return
        self._running_tool = True

        def run():
            self.call_from_thread(self._start_spinner, "AI thinking")
            response = self._call_llm()
            if not response or not response.strip():
                self.call_from_thread(self._stop_spinner)
                self.call_from_thread(self._add_chat_message, "system", "AI returned no response. Retrying...")
                self.conversation.append({"role": "user", "content": "Please continue with your analysis."})
                self._running_tool = False
                self._converse()
                return

            text_before, tool_commands = self._extract_tools(response)
            self.conversation.append({"role": "assistant", "content": response})

            if text_before:
                self.call_from_thread(self._add_chat_message, "assistant", text_before)

            if not tool_commands:
                self.call_from_thread(self._stop_spinner)
                self._running_tool = False
                return

            cmd = tool_commands[0]
            self.call_from_thread(self._start_spinner, f"running {cmd.replace('TOOL:', '').strip().split()[0]}")
            result_data = self._execute_tool(cmd)
            if result_data is None:
                self.call_from_thread(self._stop_spinner)
                self._running_tool = False
                return

            if result_data.get("error", "").startswith("Unknown tool:"):
                self.call_from_thread(self._stop_spinner)
                unknown_tool = result_data["error"].replace("Unknown tool: ", "")
                tools_list = ", ".join(t for cat in CATEGORIES_LIST for t in cat[1])
                msg = (
                    f"You tried to run '{unknown_tool}' which does not exist. "
                    f"Here are the available tools: {tools_list}. "
                    "Pick one from this list and try again."
                )
                self.conversation.append({"role": "user", "content": msg})
                self.call_from_thread(self._add_chat_message, "error", msg)
                self._running_tool = False
                return

            self.call_from_thread(self._start_spinner, "AI analyzing results")
            summary = json.dumps(result_data, indent=2, default=str)[:2000]

            self.conversation.append({
                "role": "user",
                "content": f"Tool executed: {cmd}\n\nResults:\n{summary}\n\nAnalyze these results. What are the key findings? Then ask the user what they want to do next.",
            })

            tool_name = cmd.replace("TOOL:", "").strip().split()[0]
            self.call_from_thread(self.db.add_task, tool_name, "done")
            self.call_from_thread(self.db.add_raw_result, tool_name, result_data)
            self._extract_and_add_findings(tool_name, result_data)

            next_response = self._call_llm()
            if next_response:
                self.conversation.append({"role": "assistant", "content": next_response})
                self.call_from_thread(self._add_chat_message, "assistant", next_response)

            self.call_from_thread(self._sidebar_update)
            self.call_from_thread(self._stop_spinner)
            self._running_tool = False

        threading.Thread(target=run, daemon=True).start()

    def _sidebar_update(self):
        try:
            sidebar = self.query_one("#sidebar-content")
            sidebar._update_all()
        except Exception:
            pass

    def _start_spinner(self, message="processing"):
        self._spinner_idx = 0
        self._loading_message = message
        if self._spinner_timer:
            self._spinner_timer.stop()
        self._spinner_timer = self.set_interval(0.12, self._tick_spinner)
        self._update_spinner_text()

    def _stop_spinner(self):
        if self._spinner_timer:
            self._spinner_timer.stop()
            self._spinner_timer = None
        try:
            self.query_one("#loading-indicator").update("")
        except Exception:
            pass

    def _tick_spinner(self):
        self._spinner_idx += 1
        self._update_spinner_text()

    def _update_spinner_text(self):
        chars = ["|", "/", "-", "\\"]
        char = chars[self._spinner_idx % len(chars)]
        try:
            self.query_one("#loading-indicator").update(f" {char} {self._loading_message}...")
        except Exception:
            pass

    def _extract_and_add_findings(self, tool_name, result_data):
        if not isinstance(result_data, dict):
            self.call_from_thread(self.db.add_finding, tool_name, "completed", "info")
            return
        text = json.dumps(result_data, default=str).lower()
        severity = "info"
        if any(w in text for w in ["vulnerable", "vulnerability", "critical", "exploit"]):
            severity = "critical"
        elif any(w in text for w in ["warning", "misconfig", "exposed", "risk"]):
            severity = "high"
        elif any(w in text for w in ["potential", "possible", "suspicious", "unusual"]):
            severity = "medium"

        summary = self._build_finding_summary(tool_name, result_data)
        self.call_from_thread(self.db.add_finding, tool_name, summary[:80], severity)

    def _build_finding_summary(self, tool_name, data):
        interesting_keys = [k for k in data.keys()
                           if any(w in k.lower() for w in
                                  ["vuln", "result", "found", "detect", "finding",
                                   "issue", "risk", "redirect", "csp", "path",
                                   "traversal", "expose", "config", "bypass",
                                   "engine", "parameter", "status", "error",
                                   "warning"])]
        parts = []
        for k in interesting_keys[:5]:
            v = data[k]
            if isinstance(v, list) and v:
                items = []
                for item in v[:3]:
                    if isinstance(item, dict):
                        label = str(item.get("payload", item.get("type", item.get(k.rstrip("s"), ""))))
                        if label:
                            items.append(str(label)[:40])
                    elif isinstance(item, str):
                        items.append(item[:40])
                if items:
                    parts.append(f"{k}: {', '.join(items)}")
            elif isinstance(v, dict) and v:
                subs = []
                for sk, sv in v.items():
                    if isinstance(sv, bool) and sv:
                        subs.append(sk)
                    elif isinstance(sv, (int, float)) and sv:
                        subs.append(f"{sk}={sv}")
                    elif isinstance(sv, str) and sv and sv not in ("None", "False", ""):
                        subs.append(f"{sk}={sv[:30]}")
                if subs:
                    parts.append(f"{k}: {', '.join(subs[:3])}")
            elif isinstance(v, bool):
                parts.append(f"{k}={v}")
            elif isinstance(v, str) and v and v not in ("None", "False", ""):
                parts.append(f"{k}={v[:40]}")
            elif isinstance(v, (int, float)):
                parts.append(f"{k}={v}")

        if parts:
            return "; ".join(parts)
        return "No vulnerabilities found"

    def _refresh_sidebar(self):
        sidebar = self.query_one("#sidebar-content")
        sidebar.refresh()

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

        if tool_name not in TOOLS:
            error_msg = f"Unknown tool: {tool_name}"
            self.call_from_thread(self._add_chat_message, "error", error_msg)
            return {"error": error_msg}

        tool_args = self._normalize_tool_args(tool_name, tool_args)
        if "--json" not in tool_args:
            tool_args.append("--json")

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py = os.path.join(project_root, "main.py")
        cmd = [sys.executable, main_py, tool_name] + tool_args

        self.call_from_thread(self._add_chat_message, "tool", f"[{tool_name}] running...")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            stdout, stderr = proc.communicate(timeout=120)

            if proc.returncode != 0:
                stderr_text = stderr.strip() if stderr else ""
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
                error_text = stderr_text[:300] if stderr_text else f"exit code {proc.returncode}"
                self.call_from_thread(self._add_chat_message, "result", f"[{tool_name}] error: {error_text}")
                return {"error": error_text}

            stdout = stdout.strip()
            if not stdout:
                self.call_from_thread(self._add_chat_message, "result", f"[{tool_name}] no output")
                return {"error": "no output"}

            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                json_match = re.search(r"\{.*\}", stdout, re.DOTALL)
                if json_match:
                    try:
                        data = json.loads(json_match.group())
                    except:
                        data = {"raw_output": stdout[:500]}
                else:
                    data = {"raw_output": stdout[:500]}

            self.call_from_thread(self._add_chat_message, "result", f"[{tool_name}] completed")
            return data

        except subprocess.TimeoutExpired:
            proc.kill()
            self.call_from_thread(self._add_chat_message, "error", f"[{tool_name}] timed out")
            return {"error": "timeout"}
        except Exception as e:
            self.call_from_thread(self._add_chat_message, "error", f"[{tool_name}] error: {e}")
            return {"error": str(e)}

    def _execute_tool_raw(self, tool_name, tool_args):
        if "--json" not in tool_args:
            tool_args.append("--json")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py = os.path.join(project_root, "main.py")
        cmd = [sys.executable, main_py, tool_name] + tool_args
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            stdout, stderr = proc.communicate(timeout=60)
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
