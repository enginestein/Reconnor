import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
WEBDAV_METHODS = ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "SUBSCRIBE", "UNSUBSCRIBE", "POLL", "REPORT"]
DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-HTTP-Method-Override-Original",
    "X-Original-HTTP-Method",
    "X-Override-HTTP-Method",
]

SENSITIVE_PATHS = ["/", "/admin", "/api", "/api/v1", "/api/v2", "/config", "/users", "/admin/users",
                   "/auth", "/login", "/uploads", "/files", "/backup", "/.git/config", "/WEB-INF/web.xml",
                   "/server-status", "/debug", "/test", "/secret"]

WEBDAV_PATHS = ["/", "/uploads/", "/files/", "/images/", "/assets/", "/data/", "/media/", "/backup/"]

PUT_FILE_TESTS = [
    ("test.txt", "text/plain", "hello world"),
    ("test.html", "text/html", "<html><body>test</body></html>"),
    ("test.asp", "text/plain", "<% response.write(\"test\") %>"),
    ("test.aspx", "text/plain", "<%@ Page Language=\"C#\" %>"),
    ("test.php", "text/plain", "<?php echo \"test\"; ?>"),
    ("test.jsp", "text/plain", "<% out.println(\"test\"); %>"),
    ("test.cfm", "text/plain", "<cfoutput>test</cfoutput>"),
    ("test.shtml", "text/plain", "<!--#echo var=\"DATE_LOCAL\" -->"),
]


class AdvancedHTTPMethodsScanner:
    name = "httpmethods"
    description = "Advanced HTTP method scanner (all methods, WebDAV, method override, per-path testing, PUT upload test)"

    @staticmethod
    def run(target, timeout=10):
        section(f"Advanced HTTP Methods Scanner: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        all_results = []

        section("Phase 1: Standard HTTP Method Scan on Target")
        results_standard = AdvancedHTTPMethodsScanner.test_methods(target, METHODS, timeout)
        all_results.extend(results_standard)

        section("Phase 2: WebDAV Method Scan")
        info(f"Testing WebDAV methods on target...")
        results_webdav = AdvancedHTTPMethodsScanner.test_methods(target, WEBDAV_METHODS, timeout)
        all_results.extend(results_webdav)

        for path in WEBDAV_PATHS[:3]:
            test_url = f"{base_url.rstrip('/')}{path}"
            wd_results = AdvancedHTTPMethodsScanner.test_methods(test_url, WEBDAV_METHODS, timeout)
            info(f"  WebDAV methods on {path}: {len([r for r in wd_results if r['status'] not in (405, 501)])} allowed")
            all_results.extend(wd_results)

        section("Phase 3: Method Override via Custom Headers")
        for method in ["PUT", "DELETE", "PATCH", "TRACE"]:
            for header in OVERRIDE_HEADERS:
                try:
                    resp = requests.get(target, timeout=timeout,
                        headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                            header: method,
                        })
                    if resp.status_code not in (403, 404, 405, 501, 400):
                        warning(f"[{header}: {method}] -> HTTP {resp.status_code}")
                        all_results.append({
                            "method": f"OVERRIDE:{header}={method}",
                            "status": resp.status_code, "length": len(resp.content),
                            "type": "override", "path": target,
                        })
                    else:
                        info(f"[{header}: {method}] -> HTTP {resp.status_code}")
                except:
                    pass

        section("Phase 4: Sensitive Path Method Testing")
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "PROPFIND"]:
            for path in SENSITIVE_PATHS[:10]:
                test_url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = requests.request(method, test_url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    if resp.status_code not in (403, 404, 405, 501):
                        warning(f"[{method}] {test_url} -> HTTP {resp.status_code}")
                        all_results.append({
                            "method": method, "status": resp.status_code,
                            "length": len(resp.content), "type": "sensitive_path",
                            "path": path,
                        })
                except:
                    pass

        section("Phase 5: PUT File Upload Test")
        put_allowed = [r for r in all_results if r.get("method") == "PUT" and r["status"] not in (403, 404, 405, 501)]
        if put_allowed:
            warning(f"PUT method appears allowed — testing file upload...")
            for filename, content_type, body in PUT_FILE_TESTS:
                try:
                    test_url = f"{base_url.rstrip('/')}/uploads/{filename}"
                    resp = requests.put(test_url, data=body, timeout=timeout,
                        headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                            "Content-Type": content_type,
                        })
                    if resp.status_code in (200, 201, 204):
                        error(f"PUT upload SUCCESS: {test_url} (HTTP {resp.status_code})")
                        all_results.append({
                            "method": "PUT_UPLOAD", "status": resp.status_code,
                            "length": len(resp.content), "type": "put_upload",
                            "path": f"/uploads/{filename}", "content_type": content_type,
                        })
                    elif resp.status_code == 403:
                        warning(f"PUT upload blocked (403): {test_url}")
                    else:
                        info(f"PUT upload {filename}: HTTP {resp.status_code}")
                except:
                    pass
        else:
            info("PUT method not allowed — skipping upload test")

        section("HTTP Methods Summary")
        allowed = [r for r in all_results if isinstance(r["status"], int) and r["status"] not in (403, 404, 405, 501)]
        dangerous = [r for r in allowed if r["method"] in DANGEROUS_METHODS or "OVERRIDE" in r.get("type", "")]
        uploads = [r for r in all_results if r.get("type") == "put_upload"]

        status_counts = {}
        for r in all_results:
            s = r["status"]
            status_counts[s] = status_counts.get(s, 0) + 1

        result("Total method tests", str(len(all_results)))
        result("Non-403/404/405 responses", str(len(allowed)))
        result("Dangerous methods allowed", str(len(dangerous)))

        if dangerous:
            error(f"DANGEROUS HTTP METHODS ENABLED: {len(dangerous)}")
            for d in dangerous:
                result(f"  [{d['status']}]", f"{d['method']} ({d.get('path', target[:50])})")
                if "OVERRIDE" in d.get("type", ""):
                    warning(f"       Method override via custom header")

        if uploads:
            error(f"PUT FILE UPLOAD CONFIRMED: {len(uploads)} file(s)")
            for u in uploads:
                result(f"  [{u['status']}]", f"{base_url}{u['path']} ({u.get('content_type', '?')})")

        allowed_methods_list = sorted(set(r["method"] for r in allowed))
        if allowed_methods_list:
            result("Allowed methods", ", ".join(allowed_methods_list[:15]))

        headers_list = ["Method", "Status", "Length", "Type"]
        rows = []
        for r in all_results:
            rows.append([str(r["method"]), str(r["status"]), str(r["length"]), r.get("type", "standard")])
        if len(rows) > 25:
            rows = rows[:25]
        table(headers_list, rows)

        return {"target": target, "results": all_results, "allowed_methods": allowed_methods_list}

    @staticmethod
    def test_methods(url, methods, timeout):
        results = []
        for method in methods:
            try:
                resp = requests.request(method, url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                status = resp.status_code
                length = len(resp.content)

                entry = {"method": method, "status": status, "length": length, "type": "standard", "path": url}

                if status not in (403, 404, 405, 501):
                    if method in DANGEROUS_METHODS:
                        entry["note"] = "POTENTIALLY DANGEROUS"
                        warning(f"[{method}] {url} -> {status} ({length} bytes) [DANGEROUS]")
                    else:
                        success(f"[{method}] {url} -> {status} ({length} bytes)")
                else:
                    info(f"[{method}] {url} -> {status} ({length} bytes)")

                results.append(entry)
            except requests.exceptions.Timeout:
                warning(f"[{method}] {url} -> TIMEOUT")
                results.append({"method": method, "status": "TIMEOUT", "length": 0, "type": "standard", "path": url})
            except Exception as e:
                error(f"[{method}] {url} -> {e}")
                results.append({"method": method, "status": "ERROR", "length": 0, "type": "standard", "path": url})

        return results
