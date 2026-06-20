import os
import json
import re


LLM_CONFIG = {
    "provider": os.environ.get("RECONNOR_LLM", "ollama").lower(),
    "ollama": {
        "model": os.environ.get("OLLAMA_MODEL", "dolphin3:8b"),
        "host": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
    },
    "openai": {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "api_key": os.environ.get("OPENAI_API_KEY", ""),
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    },
    "anthropic": {
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-haiku-20240307"),
        "api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
    },
    "gemini": {
        "model": os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
        "api_key": os.environ.get("GEMINI_API_KEY", ""),
    },
}


class LLMHelper:
    def __init__(self, model=None, provider=None):
        self.provider = provider or LLM_CONFIG["provider"]
        self.cfg = LLM_CONFIG
        self.model = model or self.cfg.get(self.provider, {}).get("model", "llama3.2")
        self.available = self._check()

    def _check(self):
        if self.provider == "ollama":
            return self._check_ollama()
        elif self.provider == "openai":
            return bool(self.cfg["openai"]["api_key"])
        elif self.provider == "anthropic":
            return bool(self.cfg["anthropic"]["api_key"])
        elif self.provider == "gemini":
            return bool(self.cfg["gemini"]["api_key"])
        return False

    def _check_ollama(self):
        try:
            import urllib.request
            import json
            host = self.cfg["ollama"]["host"]
            req = urllib.request.Request(f"{host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                for m in data.get("models", []):
                    if self.model in m.get("name", ""):
                        return True
                return False
        except:
            return False

    def _call(self, prompt, system="", temperature=0.3, max_tokens=1024):
        if self.provider == "ollama":
            return self._call_ollama(prompt, system, temperature, max_tokens)
        elif self.provider == "openai":
            return self._call_openai(prompt, system, temperature, max_tokens)
        elif self.provider == "anthropic":
            return self._call_anthropic(prompt, system, temperature, max_tokens)
        elif self.provider == "gemini":
            return self._call_gemini(prompt, system, temperature, max_tokens)
        return None

    def _call_ollama(self, prompt, system, temperature, max_tokens):
        try:
            import urllib.request
            host = self.cfg["ollama"]["host"]
            body = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "system": system,
                "stream": False,
                "options": {"temperature": temperature, "num_predict": max_tokens},
            }).encode()
            req = urllib.request.Request(f"{host}/api/generate", data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data.get("response", "")
        except:
            return None

    def _call_openai(self, prompt, system, temperature, max_tokens):
        try:
            import urllib.request
            cfg = self.cfg["openai"]
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            body = json.dumps({
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }).encode()
            req = urllib.request.Request(
                f"{cfg['base_url']}/chat/completions",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {cfg['api_key']}",
                },
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except:
            return None

    def _call_anthropic(self, prompt, system, temperature, max_tokens):
        try:
            import urllib.request
            cfg = self.cfg["anthropic"]
            body = json.dumps({
                "model": self.model,
                "system": system or "",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": cfg["api_key"],
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        return block["text"]
                return ""
        except:
            return None

    def _call_gemini(self, prompt, system, temperature, max_tokens):
        try:
            import urllib.request
            cfg = self.cfg["gemini"]
            contents = []
            if system:
                contents.append({"role": "user", "parts": [{"text": system + "\n" + prompt}]})
            else:
                contents.append({"role": "user", "parts": [{"text": prompt}]})
            body = json.dumps({"contents": contents}).encode()
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={cfg['api_key']}"
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                return "".join(p.get("text", "") for p in parts)
        except:
            return None

    def _parse_list(self, text):
        lines = []
        for line in text.strip().split("\n"):
            line = line.strip().strip('"').strip("'").strip("-").strip("*").strip()
            if line and not line.startswith(("#", "//", "```")):
                lines.append(line)
        return lines

    def chat(self, message, system="", temperature=0.3, max_tokens=1024):
        return self._call(message, system=system, temperature=temperature, max_tokens=max_tokens)

    def extract_json(self, text):
        text = text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            text = match.group(1).strip()
        try:
            return json.loads(text)
        except:
            pass
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            return json.loads(text[start:end])
        except:
            return None

    def generate_admin_paths(self, domain, tech_stack):
        prompt = f"Generate 20 likely admin panel URLs/paths for {domain}. Tech: {tech_stack}. Return one per line, relative paths only (e.g., /admin)."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only paths, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_dir_paths(self, domain, tech_stack):
        prompt = f"Generate 30 common directory/file paths to brute-force on {domain}. Tech: {tech_stack}. Return one per line, relative paths."
        resp = self._call(prompt, system="You are a web security testing assistant.")
        return self._parse_list(resp) if resp else []

    def generate_fuzz_payloads(self, param_name, tech_stack, response_clues):
        prompt = f"Generate 10 creative fuzzing payloads for parameter '{param_name}' on a {tech_stack} app. Response clues: {response_clues}. Cover XSS, SQLi, SSTI, LFI, RCE, etc."
        resp = self._call(prompt)
        return self._parse_list(resp) if resp else []

    def generate_sqli_payloads(self, dbms=""):
        prompt = f"Generate 15 advanced SQL injection payloads for {dbms or 'generic'}. Focus on WAF bypass and modern techniques."
        resp = self._call(prompt)
        return self._parse_list(resp) if resp else []

    def generate_xss_payloads(self, context_hint="", csp=""):
        prompt = f"Generate 15 creative XSS payloads. Context: {context_hint}. CSP: {csp}. Focus on bypasses."
        resp = self._call(prompt)
        return self._parse_list(resp) if resp else []

    def analyze_form_security(self, form_html, url):
        prompt = f"Analyze this HTML form at {url} for security issues:\n{form_html[:2000]}"
        resp = self._call(prompt, system="List security issues in this form (CSRF, autocomplete, password leak, etc.).")
        return resp

    def analyze_js_for_secrets(self, js_content, url):
        prompt = f"Analyze this JavaScript from {url} for hardcoded secrets, API keys, tokens, endpoints:\n{js_content[:3000]}"
        resp = self._call(prompt, system="List any hardcoded secrets, API keys, tokens, or interesting endpoints found.")
        return self._parse_list(resp) if resp else []

    def find_js_endpoints(self, js_content, url):
        prompt = f"Extract all API endpoints and internal routes from this JS at {url}:\n{js_content[:3000]}"
        resp = self._call(prompt, system="Return only discovered endpoints, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_redirect_bypasses(self, original_url, observed_behavior=""):
        prompt = f"Generate 10 open redirect bypass techniques for {original_url}. Behavior: {observed_behavior}"
        resp = self._call(prompt)
        return self._parse_list(resp) if resp else []

    def analyze_redirect_chain(self, chain):
        prompt = f"Analyze this redirect chain for security issues:\n{json.dumps(chain, indent=2)}"
        resp = self._call(prompt, system="Identify risks: open redirect, HTTPS downgrade, mixed content, etc.")
        return resp

    def analyze_robots_txt(self, parsed_robots, base_url):
        prompt = f"Analyze this robots.txt for {base_url} for recon opportunities:\n{json.dumps(parsed_robots, indent=2)}"
        resp = self._call(prompt, system="List interesting disallowed paths and hidden resources.")
        return resp

    def analyze_sitemap_urls(self, urls, base_url):
        prompt = f"Analyze these sitemap URLs from {base_url} for recon opportunities:\n{json.dumps(urls[:100], indent=2)}"
        resp = self._call(prompt, system="Identify interesting endpoints, hidden functionality, recon targets.")
        return resp

    def analyze_shodan_results(self, matches, search_query):
        prompt = f"Analyze these Shodan results for '{search_query}':\n{json.dumps(matches[:20], indent=2)}"
        resp = self._call(prompt, system="Summarize findings, highlight critical services, suggest next recon steps.")
        return resp

    def generate_lfi_payloads(self, target, tech_stack=None):
        prompt = f"Generate 20 LFI/RFI payloads for {target}. Tech: {tech_stack}. Include path traversal, PHP wrappers, RFI, null byte, /proc/self. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_cmd_injection_payloads(self, param_name, tech_stack=None):
        prompt = f"Generate 15 command injection payloads for parameter '{param_name}' on {tech_stack}. Include semicolon, pipe, subshell, blind time-based, OOB, WAF bypass. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_nosql_payloads(self, param_name, db_type="mongodb"):
        prompt = f"Generate 12 NoSQL injection payloads for {db_type} parameter '{param_name}'. Include $ne, $gt, $regex, $where, JSON injection. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_host_header_payloads(self, domain):
        prompt = f"Generate 12 Host header injection payloads for {domain}. Include different domain, XFH, port injection, CRLF, absolute URL. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only host header values, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_crlf_payloads(self, context_hint="parameter"):
        prompt = f"Generate 12 CRLF injection payloads for {context_hint} context. Include %0d%0a, %0a, double encoding, unicode, XSS via CRLF. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_prototype_pollution_payloads(self, framework="express"):
        prompt = f"Generate 10 server-side prototype pollution payloads for Node.js/{framework}. Include __proto__, constructor.prototype, JSON body, query string, header vectors. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_deserialization_payloads(self, language="php"):
        prompt = f"Generate 12 insecure deserialization payload snippets for {language}. Include PHP serialized objects, Python pickle, Java gadgets, Ruby YAML, .NET PS. Return one per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only payloads, one per line.")
        return self._parse_list(resp) if resp else []

    def generate_wordlist_entries(self, target, tech_stack=None, page_content=None):
        prompt = f"Generate 30 wordlist entries for {target}. Tech: {tech_stack}. Content: {page_content[:1000] if page_content else 'N/A'}. Include paths, params, endpoints, filenames, subdomains. Return one word per line."
        resp = self._call(prompt, system="You are a web security testing assistant. Return only single words, one per line.")
        return self._parse_list(resp) if resp else []

    def analyze_shodan_host(self, host_data):
        prompt = f"Analyze this Shodan host data:\n{json.dumps(host_data, indent=2)}"
        resp = self._call(prompt, system="Summarize open ports, services, vulnerabilities, and security posture.")
        return resp

    def summarize_findings(self, tool_name, target, findings):
        prompt = f"Summarize these {tool_name} findings for {target}:\n{json.dumps(findings, indent=2, default=str)[:3000]}"
        resp = self._call(prompt, system="Provide a concise security summary of the findings.")
        return resp

    def suggest_next_steps(self, target, completed_tools, findings_summary):
        prompt = f"I've run these tools on {target}: {', '.join(completed_tools)}.\nFindings: {findings_summary[:2000]}\nWhat should I do next?"
        resp = self._call(prompt, system="You are a security testing assistant. Suggest the next 3-5 recon or testing steps.")
        return resp

    def generate_report(self, target, all_results):
        prompt = f"Generate a penetration testing report for {target} based on these results:\n{json.dumps(all_results, indent=2, default=str)[:5000]}"
        resp = self._call(prompt, system="Generate a professional security assessment report with executive summary, findings table, and remediation recommendations.", temperature=0.5, max_tokens=2048)
        return resp

    def auto_recon_plan(self, target):
        prompt = f"Plan a reconnaissance engagement for {target}. List the top 10 tools to run in order."
        resp = self._call(prompt, system="Return a numbered list of recon tools to run, in priority order. Tools available: port-scan, subdomain, dns, whois, certsearch, reverseip, tech, waf, crawl, js, forms, ssl, headers, email, github, shodan, cloud, wayback, dork, cve.")
        return self._parse_list(resp) if resp else []
