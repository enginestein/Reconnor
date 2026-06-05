#!/usr/bin/env python3
import sys
import argparse

from utils.output import print_banner, info, error, section, success, warning
from tools import TOOLS, HELP_DESCRIPTIONS

EPILOG = """
EXAMPLES:
  python3 main.py port-scan example.com
  python3 main.py subdomain example.com
  python3 main.py dir-bust https://example.com --extensions
  python3 main.py dns example.com --zone-transfer
  python3 main.py whois example.com
  python3 main.py headers example.com
  python3 main.py ssl example.com
  python3 main.py wayback example.com --limit 200
  python3 main.py email example.com --crawl
  python3 main.py links https://example.com --check
  python3 main.py tech example.com
  python3 main.py metadata /path/to/file.jpg
  python3 main.py crawl https://example.com --depth 3
  python3 main.py cve log4j
  python3 main.py geoip 8.8.8.8
  python3 main.py fuzz https://example.com --params id,page
  python3 main.py dork --domain example.com --category "Login"
  python3 main.py username john
  python3 main.py certsearch example.com
  python3 main.py waf example.com
  python3 main.py reverseip example.com
  python3 main.py github john --mode user
  python3 main.py github tensorflow --mode repo
  python3 main.py github "api key" --mode search
  python3 main.py breach email@example.com
  python3 main.py breach mypassword --type password
  python3 main.py sociallinks example.com
  python3 main.py js https://example.com
  python3 main.py forms https://example.com
  python3 main.py asn 8.8.8.8
  python3 main.py asn AS15169
  python3 main.py httpmethods example.com
  python3 main.py cors example.com
  python3 main.py sqli example.com/page?id=1
  python3 main.py xss example.com/page?q=test
  python3 main.py admin example.com
  python3 main.py openredirect example.com/page?url=http://evil.com
  python3 main.py cloud example.com
  python3 main.py smtp example.com
  python3 main.py email-finder example.com
  python3 main.py email-recon john@example.com
  python3 main.py phone-info "+14155551234"
  python3 main.py phone-social "+14155551234"
  python3 main.py tor-check example.com
  python3 main.py pastewatch email@example.com
   python3 main.py deep-search "company name + credentials"
   python3 main.py mac-address 00:11:22:33:44:55
   python3 main.py favicon example.com
   python3 main.py redirects example.com
   python3 main.py redirects example.com --ollama-model llama3.2
   python3 main.py robots example.com
   python3 main.py robots example.com --ollama-model llama3.2
   python3 main.py shodan example.com
   python3 main.py shodan --query "apache 2.4.49 country:US"
   python3 main.py shodan 8.8.8.8
   python3 main.py shodan --query "http.favicon.hash:-1775126190" --limit 50
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reconnor",
        description="Educational Hacking & OSINT Suite - A collection of custom-built security analysis tools",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = sub = parser.add_subparsers(dest="tool", help="Tool to execute")

    for name, tool_cls in TOOLS.items():
        desc = HELP_DESCRIPTIONS.get(name, tool_cls.description)
        p = sub.add_parser(name, help=desc)

        if name == "port-scan":
            p.add_argument("target", help="Hostname or IP address")
            p.add_argument("--ports", "-p", help="Port range (e.g., 1-1000 or 22,80,443)")
            p.add_argument("--timeout", type=int, default=2, help="Connection timeout (seconds)")
            p.add_argument("--threads", type=int, default=100, help="Max threads")

        elif name == "subdomain":
            p.add_argument("target", help="Target domain")
            p.add_argument("--wordlist", "-w", help="Custom subdomain wordlist file")
            p.add_argument("--threads", type=int, default=50, help="Max threads")

        elif name == "dir-bust":
            p.add_argument("target", help="Target URL")
            p.add_argument("--wordlist", "-w", help="Custom path wordlist file")
            p.add_argument("--extensions", "-e", action="store_true", help="Try common extensions")
            p.add_argument("--threads", type=int, default=30, help="Max threads")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted path generation")

        elif name == "dns":
            p.add_argument("target", help="Domain to query")
            p.add_argument("--zone-transfer", "-z", action="store_true", help="Attempt DNS zone transfer")

        elif name == "whois":
            p.add_argument("target", help="Domain or IP address")

        elif name == "headers":
            p.add_argument("target", help="Target URL")

        elif name == "ssl":
            p.add_argument("target", help="Hostname or URL")
            p.add_argument("--port", type=int, default=443, help="Port number")

        elif name == "wayback":
            p.add_argument("target", help="Domain")
            p.add_argument("--limit", "-l", type=int, default=500, help="Max snapshots")
            p.add_argument("--all", "-a", action="store_true", help="Show all snapshots")

        elif name == "email":
            p.add_argument("target", help="Target URL")
            p.add_argument("--crawl", "-c", action="store_true", help="Crawl linked pages")
            p.add_argument("--depth", type=int, default=1, help="Crawl depth")
            p.add_argument("--max", type=int, default=20, help="Max pages")

        elif name == "links":
            p.add_argument("target", help="Target URL")
            p.add_argument("--check", action="store_true", help="Check link health")
            p.add_argument("--threads", type=int, default=20, help="Max threads")

        elif name == "tech":
            p.add_argument("target", help="Target URL or domain")

        elif name == "metadata":
            p.add_argument("target", help="File path or directory")

        elif name == "crawl":
            p.add_argument("target", help="Target URL")
            p.add_argument("--depth", type=int, default=2, help="Max crawl depth")
            p.add_argument("--max-urls", type=int, default=100, dest="max_urls", help="Max URLs")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "cve":
            p.add_argument("target", help="Search term")
            p.add_argument("--limit", type=int, default=20, help="Max results")

        elif name == "geoip":
            p.add_argument("target", help="IP, domain, or 'me'")

        elif name == "fuzz":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Custom parameters (comma-separated)")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "dork":
            p.add_argument("--domain", "-d", help="Scope to domain")
            p.add_argument("--category", "-c", help="Filter by category")

        elif name == "username":
            p.add_argument("target", help="Username to search")
            p.add_argument("--platforms", "-p", help="Filter by platform names (comma-sep)")
            p.add_argument("--threads", type=int, default=50, help="Max threads")

        elif name == "certsearch":
            p.add_argument("target", help="Domain to search")
            p.add_argument("--all", "-a", action="store_true", help="Show all entries (not just unique)")

        elif name == "waf":
            p.add_argument("target", help="Target URL")

        elif name == "reverseip":
            p.add_argument("target", help="Domain or IP address")

        elif name == "github":
            p.add_argument("target", help="Username or repo (user/repo)")
            p.add_argument("--mode", choices=["user", "repo", "search"], default="user",
                          help="Query mode: user info, repo info, or code search")

        elif name == "breach":
            p.add_argument("target", help="Email, password, or username")
            p.add_argument("--type", choices=["email", "password", "username"], default="email",
                          help="Type of data to check")

        elif name == "sociallinks":
            p.add_argument("target", help="Target URL")

        elif name == "js":
            p.add_argument("target", help="Target URL")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted JS analysis")

        elif name == "forms":
            p.add_argument("target", help="Target URL")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted form analysis")

        elif name == "asn":
            p.add_argument("target", help="IP, domain, or AS number (e.g., AS15169)")

        elif name == "httpmethods":
            p.add_argument("target", help="Target URL")

        elif name == "cors":
            p.add_argument("target", help="Target URL")

        elif name == "sqli":
            p.add_argument("target", help="Target URL")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted SQLi payload generation")

        elif name == "xss":
            p.add_argument("target", help="Target URL")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted XSS payload generation")

        elif name == "admin":
            p.add_argument("target", help="Target URL")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted path generation")

        elif name == "openredirect":
            p.add_argument("target", help="Target URL")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted redirect bypass generation")

        elif name == "cloud":
            p.add_argument("target", help="Target domain or bucket name")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "smtp":
            p.add_argument("target", help="Target domain")
            p.add_argument("--port", type=int, default=25, help="SMTP port")
            p.add_argument("--timeout", type=int, default=10, help="Connection timeout")

        elif name == "email-finder":
            p.add_argument("target", help="Domain name")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "email-recon":
            p.add_argument("target", help="Email address")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "phone-info":
            p.add_argument("target", help="Phone number (with or without + prefix)")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "phone-social":
            p.add_argument("target", help="Phone number (with or without + prefix)")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "tor-check":
            p.add_argument("target", help="Domain name or IP address")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "pastewatch":
            p.add_argument("target", help="Email, domain, or keyword to search")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "deep-search":
            p.add_argument("target", help="Search query")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "mac-address":
            p.add_argument("target", help="MAC address (e.g., 00:11:22:33:44:55)")

        elif name == "favicon":
            p.add_argument("target", help="Target URL or domain")

        elif name == "redirects":
            p.add_argument("target", help="Target URL or domain")
            p.add_argument("--ollama-model", help="Ollama model for AI analysis")

        elif name == "robots":
            p.add_argument("target", help="Target URL or domain")
            p.add_argument("--ollama-model", help="Ollama model for AI analysis")

        elif name == "shodan":
            p.add_argument("target", nargs="?", help="Domain or IP to look up")
            p.add_argument("--query", "-q", help="Shodan search query (instead of target)")
            p.add_argument("--limit", "-l", type=int, default=20, help="Max results")
            p.add_argument("--ollama-model", help="Ollama model for AI analysis")

    return parser


def main():
    if len(sys.argv) == 1:
        print_banner()
        print("Available tools:")
        for name in sorted(TOOLS.keys()):
            desc = HELP_DESCRIPTIONS.get(name, TOOLS[name].description)
            print(f"  {name:<15s} {desc}")
        print()
        print("Use 'python3 main.py <tool> --help' for tool-specific options")
        print("Examples: python3 main.py --help")
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    tool_name = args.tool
    tool_cls = TOOLS[tool_name]
    tool_kwargs = vars(args).copy()
    tool_kwargs.pop("tool")

    section(f"Running: {HELP_DESCRIPTIONS.get(tool_name, tool_cls.description)}")

    try:
        result = tool_cls.run(**tool_kwargs)
        print()
        return result
    except KeyboardInterrupt:
        print()
        warning("Operation interrupted by user")
        sys.exit(130)
    except Exception as e:
        error(f"Tool failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
