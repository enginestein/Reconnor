import requests
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table

class RedirectTracker:
    name = "redirects"
    description = "Trace and analyze HTTP redirect chains"

    @staticmethod
    def run(target, ollama_model=None):
        section(f"Redirect Chain Tracker: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        chain = []
        current_url = target
        visited = set()
        max_hops = 20
        timeout = 15

        info("Tracing redirect chain...")

        for hop in range(max_hops):
            if current_url in visited:
                warning(f"Redirect loop detected at hop {hop}: {current_url}")
                break
            visited.add(current_url)

            try:
                resp = requests.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
                )

                chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "location": resp.headers.get("Location", ""),
                    "set_cookie": resp.headers.get("Set-Cookie", ""),
                    "server": resp.headers.get("Server", ""),
                })

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if not location:
                        break
                    current_url = location
                    if not current_url.startswith(("http://", "https://")):
                        parsed = urlparse(current_url)
                        base_parsed = urlparse(chain[0]["url"])
                        current_url = f"{base_parsed.scheme}://{base_parsed.netloc}{current_url}"
                else:
                    break

            except requests.exceptions.SSLError:
                chain.append({"hop": hop + 1, "url": current_url, "status": "SSL_ERROR"})
                error(f"SSL error at {current_url}")
                break
            except requests.exceptions.ConnectionError as e:
                chain.append({"hop": hop + 1, "url": current_url, "status": "CONNECTION_ERROR"})
                error(f"Connection error at {current_url}: {e}")
                break
            except requests.exceptions.RequestException as e:
                chain.append({"hop": hop + 1, "url": current_url, "status": "REQUEST_ERROR"})
                error(f"Request error at {current_url}: {e}")
                break

        if not chain:
            error("No redirect chain recorded")
            return {"target": target, "chain": []}

        section("Redirect Chain")
        table(
            ["HOP", "STATUS", "URL"],
            [(str(h["hop"]), str(h["status"]), h["url"][:90]) for h in chain]
        )

        final = chain[-1]
        if final["status"] in (301, 302, 303, 307, 308):
            warning(f"Chain ends with a redirect (no final 200) — possible infinite redirect")
        elif final["status"] == 200:
            success(f"Chain resolved to {final['hop']} hop(s): {final['url']}")
        elif final["status"] in ("SSL_ERROR", "CONNECTION_ERROR", "REQUEST_ERROR"):
            error(f"Chain broken at hop {final['hop']}: {final['status']}")

        section("Security Analysis")
        security_issues = []

        for h in chain:
            if isinstance(h["status"], int) and h["status"] >= 400:
                security_issues.append(f"Hop {h['hop']}: HTTP {h['status']} — possible error")

        for i in range(len(chain) - 1):
            current_scheme = urlparse(chain[i]["url"]).scheme
            next_scheme = urlparse(chain[i + 1]["url"]).scheme
            if current_scheme == "https" and next_scheme == "http":
                security_issues.append(f"Hop {chain[i + 1]['hop']}: HTTPS → HTTP downgrade")
                warning(f"HTTPS → HTTP downgrade at hop {chain[i + 1]['hop']}")

        scheme = urlparse(chain[-1]["url"]).scheme
        if chain[0]["url"] != chain[-1]["url"] and scheme != "https":
            security_issues.append("Final URL is not HTTPS")
            warning("Final URL is not HTTPS — possible security issue")

        if security_issues:
            for issue in security_issues:
                warning(issue)
        else:
            success("No security issues detected in redirect chain")

        section("Headers Per Hop")
        for h in chain:
            if isinstance(h["status"], int):
                info(f"Hop {h['hop']} ({h['status']}): Server={h['server']}, Cookie={'Yes' if h['set_cookie'] else 'No'}")

        if ollama_model:
            try:
                from utils.ollama_helper import OllamaHelper
                ollama = OllamaHelper(model=ollama_model)
                if ollama.available:
                    chain_simple = [{"hop": h["hop"], "status": h["status"],
                                     "url": h["url"], "server": h["server"]}
                                    for h in chain]
                    ai_analysis = ollama.analyze_redirect_chain(chain_simple)
                    section("AI Analysis")
                    print(ai_analysis)
            except Exception as e:
                warning(f"AI analysis unavailable: {e}")

        return {"target": target, "chain": chain, "hops": len(chain)}
