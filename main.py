#!/usr/bin/env python3
import sys
import argparse

from utils.output import print_banner, info, error, section, success, warning
from tools import TOOLS, HELP_DESCRIPTIONS

EPILOG = """
EXAMPLES:
  python3 main.py port-scan example.com
  python3 main.py port-scan example.com --nmap
  python3 main.py subdomain example.com
  python3 main.py subdomain example.com --ext
  python3 main.py dir-bust https://example.com --extensions
  python3 main.py dir-bust https://example.com --ext -w /path/to/wordlist.txt
  python3 main.py dns example.com --ext

SETUP:
  reconnor-setup    # Install all system + external tool dependencies
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
  python3 main.py email-security example.com
  python3 main.py email-security example.com --selector google
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
   python3 main.py malware-hunt example.com
   python3 main.py malware-hunt 185.130.5.173 --type ip
   python3 main.py malware-hunt 44d88612fea8a8f36de82e1278abb02f --type hash
   python3 main.py malware-hunt "emotet" --type keyword
   python3 main.py c2-hunt example.com --check-paths
   python3 main.py c2-hunt 185.130.5.173 --port 8080
   python3 main.py phish-hunt example.com --deep
   python3 main.py phish-hunt "paypal" --deep
   python3 main.py telegram-osint @channel_name --deep
   python3 main.py telegram-osint username --limit 50
   python3 main.py reddit-osint some_user
   python3 main.py reddit-osint programming --mode subreddit
   python3 main.py reddit-osint "keyword" --mode search
   python3 main.py social-recon username --threads 150

  python3 main.py auto-recon example.com --ext --light
  python3 main.py auto-recon example.com --use-ai --llm-provider openai

  python3 main.py jwt --token eyJhbGciOiJIUzI1NiIs...
  python3 main.py jwt --token eyJ... --crack --wordlist rockyou.txt
  python3 main.py ssrf --url "http://example.com/page?url=SSRF"
  python3 main.py ssrf --url "http://example.com/page?url=SSRF" --blind
  python3 main.py lfi-rfi https://example.com/page?file=test
  python3 main.py lfi-rfi https://example.com --params file,page,path --ollama-model llama3.2
  python3 main.py cmd-injection https://example.com/ping?host=test
  python3 main.py cmd-injection https://example.com --params ip,host,domain --ollama-model llama3.2
  python3 main.py nosqli https://example.com/login?username=admin
  python3 main.py nosqli https://example.com/api/login --method POST --data '{"username":"admin","password":"test"}'
  python3 main.py takeover --domain sub.example.com
  python3 main.py takeover --domains sub1.example.com,sub2.example.com
  python3 main.py brute --url http://example.com/login --user admin
  python3 main.py brute --url http://example.com/wp-login.php --user-file users.txt --pass-file pass.txt
   python3 main.py report --input results.json --format html
   python3 main.py report --input scan1.json,scan2.json --output report.html --title "Pentest Report"
  python3 main.py graphql https://api.example.com/graphql
  python3 main.py graphql https://api.example.com/graphql --auth-bypass
  python3 main.py api-fuzz https://api.example.com --inject-headers --rate-limit
  python3 main.py smuggle example.com --port 80
  python3 main.py ws wss://example.com/ws --fuzz --dos
  python3 main.py race https://example.com/coupon --threads 50
  python3 main.py ssti https://example.com/page?name=test
  python3 main.py ssti https://example.com/page?name=test --rce
  python3 main.py xxe https://example.com/xml --file-read /etc/passwd
  python3 main.py host-header-injection https://example.com
  python3 main.py crlf-injection https://example.com/page?file=test
  python3 main.py crlf-injection https://example.com --params file,url,next --ollama-model llama3.2
  python3 main.py proto-pollution https://example.com/api/user
  python3 main.py proto-pollution https://example.com --method POST --ollama-model llama3.2
  python3 main.py deserialize https://example.com/api/upload
  python3 main.py deserialize https://example.com --param data --ollama-model llama3.2
  python3 main.py screenshot https://example.com
  python3 main.py screenshot https://example.com --output-dir reports --full-page
  python3 main.py wordlist https://example.com --size large --mutation
  python3 main.py wordlist https://example.com --output custom.txt --depth 3 --ollama-model llama3.2
  python3 main.py net-scan --subnet 192.168.1.0/24 --ping --os-detect
  python3 main.py snmp 192.168.1.1 --walk
  python3 main.py smb 192.168.1.1 --dump
  python3 main.py nfs 192.168.1.1
  python3 main.py ldap 192.168.1.1 --dump
  python3 main.py rpc 192.168.1.1
  python3 main.py cred-spray https://example.com/login --username admin --passwords Password1,Welcome1
  python3 main.py cred-spray https://example.com/login --user-file users.txt --pass-file pass.txt
  python3 main.py default-creds https://example.com --category router
  python3 main.py default-creds https://example.com --service tomcat
  python3 main.py pass-analyze --password MyP@ssw0rd!
  python3 main.py hash-id --hash 5d41402abc4b2a76b9719d911017c592 --crack
  python3 main.py aws-enum --target example.com --s3 --metadata
  python3 main.py k8s 192.168.1.100 --full
  python3 main.py container 192.168.1.100 --breakout
  python3 main.py cloud-meta --check-all
  python3 main.py project --cmd init --name engagement1 --target example.com
  python3 main.py project --cmd save --project engagement1 --tool port-scan --file results.json
  python3 main.py project --cmd compare --compare 1,2
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
        p.add_argument("--json", action="store_true", help="Output results as JSON")
        p.add_argument("--output", "-o", help="Write output to file")

        if name == "port-scan":
            p.add_argument("target", help="Hostname or IP address")
            p.add_argument("--ports", "-p", help="Port range (e.g., 1-1000 or 22,80,443)")
            p.add_argument("--timeout", type=int, default=2, help="Connection timeout (seconds)")
            p.add_argument("--threads", type=int, default=100, help="Max threads")
            p.add_argument("--nmap", action="store_true", help="Use nmap for service/version detection")

        elif name == "subdomain":
            p.add_argument("target", help="Target domain")
            p.add_argument("--wordlist", "-w", help="Custom subdomain wordlist file")
            p.add_argument("--threads", type=int, default=50, help="Max threads")
            p.add_argument("--ext", action="store_true", help="Use external tools (sublist3r, amass, assetfinder)")

        elif name == "dir-bust":
            p.add_argument("target", help="Target URL")
            p.add_argument("--wordlist", "-w", help="Custom path wordlist file")
            p.add_argument("--extensions", "-e", action="store_true", help="Try common extensions")
            p.add_argument("--threads", type=int, default=30, help="Max threads")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted path generation")
            p.add_argument("--ext", action="store_true", help="Use external tools (ffuf, gobuster)")

        elif name == "dns":
            p.add_argument("target", help="Domain to query")
            p.add_argument("--zone-transfer", "-z", action="store_true", help="Attempt DNS zone transfer")
            p.add_argument("--ext", action="store_true", help="Use external tools (dnsrecon, dig, host)")

        elif name == "whois":
            p.add_argument("target", help="Domain or IP address")

        elif name == "headers":
            p.add_argument("target", help="Target URL")

        elif name == "ssl":
            p.add_argument("target", help="Hostname or URL")
            p.add_argument("--port", type=int, default=443, help="Port number")
            p.add_argument("--ext", action="store_true", help="Use openssl for deeper TLS analysis")

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
            p.add_argument("--ext", action="store_true", help="Use whatweb for enhanced technology detection")

        elif name == "metadata":
            p.add_argument("target", help="File path or directory")

        elif name == "crawl":
            p.add_argument("target", help="Target URL")
            p.add_argument("--depth", type=int, default=2, help="Max crawl depth")
            p.add_argument("--max-urls", type=int, default=100, dest="max_urls", help="Max URLs")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ext", action="store_true", help="Use gospider/hakrawler for enhanced crawling")

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
            p.add_argument("--variants", action="store_true", help="Try all case variations (lower, upper, capitalized)")

        elif name == "certsearch":
            p.add_argument("target", help="Domain to search")
            p.add_argument("--all", "-a", action="store_true", help="Show all entries (not just unique)")

        elif name == "waf":
            p.add_argument("target", help="Target URL")
            p.add_argument("--ext", action="store_true", help="Use wafw00f for enhanced WAF detection")

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
            p.add_argument("--ext", action="store_true", help="Use subjs/linkfinder for JS discovery")

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
            p.add_argument("--limit", type=int, default=20, help="Max results per source")
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

        elif name == "malware-hunt":
            p.add_argument("target", help="Domain, IP, hash (sha256), or keyword to hunt")
            p.add_argument("--type", choices=["domain", "ip", "hash", "keyword"], default="domain",
                          help="Type of search target")
            p.add_argument("--limit", type=int, default=25, help="Max results per source")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")

        elif name == "c2-hunt":
            p.add_argument("target", help="Domain, IP, or URL to investigate for C2 infrastructure")
            p.add_argument("--port", type=int, default=443, help="Port for SSL fingerprinting")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--check-paths", action="store_true", help="Brute force C2 panel paths")

        elif name == "phish-hunt":
            p.add_argument("target", help="Domain, URL, or keyword to hunt for phishing infrastructure")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--deep", "-d", action="store_true", help="Deep scan (dorking + cred leak check)")

        elif name == "telegram-osint":
            p.add_argument("target", help="Telegram username, channel, or group (with or without @)")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--limit", type=int, default=20, help="Max messages to analyze")
            p.add_argument("--deep", "-d", action="store_true", help="Deep scan (related channels)")

        elif name == "reddit-osint":
            p.add_argument("target", help="Reddit username, subreddit, or search query")
            p.add_argument("--mode", choices=["user", "subreddit", "search"], default="user",
                          help="Search mode: user profile, subreddit info, or keyword search")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--limit", type=int, default=25, help="Max items to analyze")

        elif name == "social-recon":
            p.add_argument("target", help="Username to search across 60+ social platforms")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=100, help="Max concurrent checks")

        elif name == "auto-recon":
            p.add_argument("target", help="Target domain or URL")
            p.add_argument("--use-ai", action="store_true", help="Enable AI-driven decision making")
            p.add_argument("--llm-provider", default="", help="LLM provider (ollama, openai, anthropic, gemini)")
            p.add_argument("--llm-model", default="", help="LLM model name")
            p.add_argument("--light", action="store_true", help="Run lighter tool chain (skip crawl, js, forms)")
            p.add_argument("--threads", type=int, default=50, help="Max threads per tool")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ext", action="store_true", help="Use external tools where available")
            p.add_argument("--nmap", action="store_true", help="Use nmap for port scan")


        elif name == "jwt":
            p.add_argument("--token", help="JWT token to analyze")
            p.add_argument("--crack", action="store_true", help="Attempt to crack the JWT secret")
            p.add_argument("--wordlist", "-w", help="Wordlist for JWT cracking")
            p.add_argument("--alg", help="Algorithm confusion test (e.g., HS256)")
            p.add_argument("--target", help="Target server URL for sending modified tokens")
            p.add_argument("--kid-knject", dest="kid_inject", help="KID injection payload")
            p.add_argument("--jwki-url", help="JWK confusion target URL")

        elif name == "ssrf":
            p.add_argument("--url", help="Target URL with injection point (use =SSRF as placeholder)")
            p.add_argument("--urls", help="Comma-separated list of target URLs")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data (use $param as placeholder)")
            p.add_argument("--headers", dest="headers_json", help="Custom headers as JSON")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=10, help="Max threads")
            p.add_argument("--blind", action="store_true", help="Enable blind SSRF (out-of-band) testing")
            p.add_argument("--collaborator", help="Custom collaborator URL (default: interactsh)")

        elif name == "takeover":
            p.add_argument("--domain", help="Single domain to check")
            p.add_argument("--domains", help="Comma-separated list of domains")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "brute":
            p.add_argument("--url", help="Target URL for login page")
            p.add_argument("--username", "--user", help="Single username")
            p.add_argument("--usernames", help="Comma-separated username list")
            p.add_argument("--password", "--pass", help="Single password")
            p.add_argument("--passwords", help="Comma-separated password list")
            p.add_argument("--user-file", help="File with usernames")
            p.add_argument("--pass-file", help="File with passwords")
            p.add_argument("--method", default="auto", help="Auth method (auto/form/basic)")
            p.add_argument("--field-user", default="", help="Username form field name")
            p.add_argument("--field-pass", default="", help="Password form field name")
            p.add_argument("--auth-type", default="", help="Force auth type (form/basic)")
            p.add_argument("--success-str", help="String indicating login success")
            p.add_argument("--fail-str", help="String indicating login failure")
            p.add_argument("--threads", type=int, default=10, help="Max threads")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--delay", type=float, default=0, help="Delay between attempts (seconds)")

        elif name == "report":
            p.add_argument("--input", required=True, help="Comma-separated JSON result files")
            p.add_argument("--format", default="html", choices=["html", "json", "txt"], help="Report format")
            p.add_argument("--title", default="", help="Report title")
            p.add_argument("--author", default="", help="Report author")
            p.add_argument("--target", help="Target description")
            p.add_argument("--domain", help="Target domain")
            p.add_argument("--url", help="Target URL")

        elif name == "graphql":
            p.add_argument("--url", help="GraphQL endpoint URL")
            p.add_argument("--target", help="Target domain (auto-discovers endpoint)")
            p.add_argument("--query", help="Custom GraphQL query")
            p.add_argument("--no-introspection", action="store_true", dest="introspection", help="Skip introspection")
            p.add_argument("--no-batch", action="store_true", dest="batch", help="Skip batch testing")
            p.add_argument("--no-depth", action="store_true", dest="depth", help="Skip depth testing")
            p.add_argument("--auth-bypass", action="store_true", dest="auth_bypass", help="Test auth bypass")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")

        elif name == "api-fuzz":
            p.add_argument("--url", help="Target API URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="Request body data")
            p.add_argument("--headers", dest="headers_json", help="Custom headers as JSON")
            p.add_argument("--params", help="Custom parameters")
            p.add_argument("--inject-headers", action="store_true", help="Test header injection")
            p.add_argument("--pollute", action="store_true", help="Test parameter pollution")
            p.add_argument("--rate-limit", action="store_true", dest="rate_limit", help="Test rate limiting")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")

        elif name == "smuggle":
            p.add_argument("--target", help="Target hostname")
            p.add_argument("--url", help="Target URL (alias for --target)")
            p.add_argument("--port", type=int, default=80, help="Target port")
            p.add_argument("--tls", action="store_true", help="Use TLS")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "ws":
            p.add_argument("--url", help="WebSocket URL (ws:// or wss://)")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--origin", help="Custom origin header to test")
            p.add_argument("--message", help="Custom message to send")
            p.add_argument("--fuzz", action="store_true", help="Fuzz WebSocket messages")
            p.add_argument("--dos", action="store_true", help="Test DoS resistance")
            p.add_argument("--timeout", type=int, default=15, help="Connection timeout")

        elif name == "race":
            p.add_argument("--url", help="Target URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--method", default="GET", help="HTTP method")
            p.add_argument("--data", help="Request body")
            p.add_argument("--headers", dest="headers_json", help="Custom headers as JSON")
            p.add_argument("--threads", type=int, default=50, help="Number of concurrent requests")
            p.add_argument("--param", help="Parameter to vary")
            p.add_argument("--delay", type=float, default=0, help="Delay between requests")
            p.add_argument("--scenario", default="generic", help="Test scenario (coupon/otp/rate)")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")

        elif name == "ssti":
            p.add_argument("--url", help="Target URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--params", help="Comma-separated parameter names")
            p.add_argument("--method", default="GET", help="HTTP method")
            p.add_argument("--data", help="POST data")
            p.add_argument("--rce", action="store_true", help="Attempt RCE exploitation")
            p.add_argument("--file-read", help="File to read via SSTI")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=10, help="Max threads")

        elif name == "xxe":
            p.add_argument("--url", help="Target URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--data", help="Raw XML data")
            p.add_argument("--param", help="Parameter name holding XML")
            p.add_argument("--content-type", help="Content-Type header value")
            p.add_argument("--file-read", help="File to read via XXE")
            p.add_argument("--collaborator", help="OOB collaborator URL")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")

        elif name == "net-scan":
            p.add_argument("--target", help="Single target host")
            p.add_argument("--subnet", help="CIDR subnet (e.g., 192.168.1.0/24)")
            p.add_argument("--ports", default="22,80,443,3306,3389,8080,8443", help="Ports to scan")
            p.add_argument("--no-ping", action="store_false", dest="ping", help="Skip ping sweep")
            p.add_argument("--arp", action="store_true", help="Show ARP table")
            p.add_argument("--os-detect", action="store_true", help="Attempt OS fingerprinting")
            p.add_argument("--threads", type=int, default=100, help="Max threads")
            p.add_argument("--timeout", type=int, default=5, help="Socket timeout")

        elif name == "snmp":
            p.add_argument("--target", help="Target host")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--community", help="SNMP community string to use")
            p.add_argument("--walk", action="store_true", help="Walk MIB tree (interfaces, users, processes)")
            p.add_argument("--port", type=int, default=161, help="SNMP port")
            p.add_argument("--timeout", type=int, default=5, help="Socket timeout")

        elif name == "smb":
            p.add_argument("--target", help="Target host")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--port", type=int, default=445, help="SMB port")
            p.add_argument("--dump", action="store_true", help="Full enumeration (shares + users)")
            p.add_argument("--null-session", action="store_true", help="Test null session")
            p.add_argument("--list-shares", action="store_true", help="List SMB shares")
            p.add_argument("--enum-users", action="store_true", help="Enumerate users")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "nfs":
            p.add_argument("--target", help="Target host")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--port", type=int, default=2049, help="NFS port")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "ldap":
            p.add_argument("--target", help="Target host")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--port", type=int, default=389, help="LDAP port")
            p.add_argument("--base-dn", help="LDAP base DN")
            p.add_argument("--dump", action="store_true", help="Dump users and groups")
            p.add_argument("--ssl", action="store_true", help="Use LDAPS")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "rpc":
            p.add_argument("--target", help="Target host")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--port", type=int, default=111, help="RPC port")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "cred-spray":
            p.add_argument("--url", help="Target login URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--username", help="Single username")
            p.add_argument("--usernames", help="Comma-separated usernames")
            p.add_argument("--user-file", help="File with usernames")
            p.add_argument("--password", help="Single password")
            p.add_argument("--passwords", help="Password list")
            p.add_argument("--pass-file", help="File with passwords")
            p.add_argument("--delay", type=int, default=2, help="Delay between attempts")
            p.add_argument("--lockout-threshold", type=int, default=5, help="Lockout threshold")
            p.add_argument("--max-attempts", type=int, default=3, help="Passwords per user")
            p.add_argument("--field-user", default="username", help="Username field name")
            p.add_argument("--field-pass", default="password", help="Password field name")
            p.add_argument("--fail-str", default="invalid", help="Login failure string")
            p.add_argument("--timeout", type=int, default=15, help="HTTP timeout")

        elif name == "default-creds":
            p.add_argument("--url", help="Target URL")
            p.add_argument("--target", help="Target (alias for --url)")
            p.add_argument("--service", help="Filter by service name")
            p.add_argument("--category", help="Filter by category (router/firewall/web/db/cms/iot/service)")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")

        elif name == "pass-analyze":
            p.add_argument("--password", help="Single password to analyze")
            p.add_argument("--passwords", help="Comma-separated password list")
            p.add_argument("--min-len", type=int, default=8, help="Minimum password length")
            p.add_argument("--no-common", action="store_false", dest="check_common", help="Skip common password check")
            p.add_argument("--verbose", action="store_true", help="Verbose output")

        elif name == "hash-id":
            p.add_argument("--hash", help="Single hash to identify")
            p.add_argument("--hashes", help="Comma-separated hashes")
            p.add_argument("--crack", action="store_true", help="Attempt cracking")
            p.add_argument("--wordlist", "-w", help="Wordlist for cracking")
            p.add_argument("--info", action="store_true", dest="show_info", help="Show hash info")

        elif name == "aws-enum":
            p.add_argument("--target", help="Target domain")
            p.add_argument("--bucket", help="Single bucket name to check")
            p.add_argument("--s3", action="store_true", dest="s3_check", help="Check S3 buckets")
            p.add_argument("--iam", action="store_true", dest="iam_check", help="Test IAM API")
            p.add_argument("--ec2", action="store_true", dest="ec2_check", help="Check EC2 metadata")
            p.add_argument("--sts", action="store_true", dest="sts_check", help="Test STS API")
            p.add_argument("--metadata", action="store_true", help="Test EC2 metadata service")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")

        elif name == "k8s":
            p.add_argument("--target", help="Target hostname/IP")
            p.add_argument("--url", help="Target URL (alias)")
            p.add_argument("--port", type=int, default=0, help="API server port")
            p.add_argument("--full", action="store_true", help="Full audit")
            p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "container":
            p.add_argument("--target", help="Target hostname/IP")
            p.add_argument("--host", help="Host alias")
            p.add_argument("--port", type=int, default=0, help="Docker API port")
            p.add_argument("--socket", help="Docker socket path")
            p.add_argument("--breakout", action="store_true", help="Test container breakout")
            p.add_argument("--images", action="store_true", help="Check container images")
            p.add_argument("--timeout", type=int, default=10, help="Socket timeout")

        elif name == "cloud-meta":
            p.add_argument("--target", help="Target (unused, scans from current host)")
            p.add_argument("--provider", help="Single provider to check (AWS/GCP/Azure/etc)")
            p.add_argument("--check-all", action="store_true", dest="check_all", help="Check all providers")
            p.add_argument("--timeout", type=int, default=5, help="HTTP timeout")

        elif name == "project":
            p.add_argument("--cmd", required=True, help="Command: init/list/save/runs/show/compare/delete")
            p.add_argument("--name", help="Project or run name")
            p.add_argument("--project", help="Project name")
            p.add_argument("--target", help="Target description")
            p.add_argument("--tool-name", help="Tool name")
            p.add_argument("--file", help="Result JSON file to save")
            p.add_argument("--runs", action="store_true", dest="list_runs", help="List runs")
            p.add_argument("--compare", help="Compare run IDs (comma-sep)")
            p.add_argument("--timeout", type=int, default=5, help="Operation timeout")

        elif name == "ai-chat":
            p.add_argument("prompt", nargs="?", help="Question or task (omit for interactive mode)")
            p.add_argument("--model", help="LLM model override")
            p.add_argument("--provider", help="LLM provider override (ollama/openai/anthropic/gemini)")
            p.add_argument("--cli", action="store_true", help="Use original CLI mode instead of TUI")

        elif name == "cmd-injection":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Comma-separated parameter names to test")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "crlf-injection":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Comma-separated parameter names to test")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "deserialize":
            p.add_argument("target", help="Target URL")
            p.add_argument("--param", default="data", help="Parameter name containing serialized data")
            p.add_argument("--method", default="POST", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="Raw POST data")
            p.add_argument("--content-type", help="Content-Type header value")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "email-security":
            p.add_argument("target", help="Domain name")
            p.add_argument("--selector", default="default", help="DKIM selector name")
            p.add_argument("--timeout", type=int, default=10, help="DNS query timeout")

        elif name == "host-header-injection":
            p.add_argument("target", help="Target URL")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "lfi-rfi":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Comma-separated parameter names to test")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "nosqli":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Comma-separated parameter names to test")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--threads", type=int, default=20, help="Max threads")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "proto-pollution":
            p.add_argument("target", help="Target URL")
            p.add_argument("--params", help="Comma-separated parameter names to test")
            p.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
            p.add_argument("--data", help="POST data")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted payload generation")

        elif name == "screenshot":
            p.add_argument("target", help="Target URL")
            p.add_argument("--output-dir", default="screenshots", help="Output directory for screenshots")
            p.add_argument("--width", type=int, default=1280, help="Viewport width")
            p.add_argument("--height", type=int, default=720, help="Viewport height")
            p.add_argument("--full-page", action="store_true", help="Capture full page (not just viewport)")
            p.add_argument("--delay", type=int, default=0, help="Delay before capture (seconds)")
            p.add_argument("--timeout", type=int, default=30, help="Navigation timeout")

        elif name == "wordlist":
            p.add_argument("target", help="Target URL to scrape")
            p.add_argument("--depth", type=int, default=2, help="Crawl depth")
            p.add_argument("--out", help="Output wordlist file path")
            p.add_argument("--size", choices=["small", "medium", "large"], default="medium",
                          help="Wordlist size (small=200, medium=500, large=1000+ common words)")
            p.add_argument("--min-len", type=int, default=3, help="Minimum word length")
            p.add_argument("--max-len", type=int, default=30, help="Maximum word length")
            p.add_argument("--mutation", action="store_true", help="Enable leetspeak and case mutations")
            p.add_argument("--timeout", type=int, default=10, help="HTTP timeout")
            p.add_argument("--ollama-model", help="Ollama model for AI-assisted word generation")

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

    tool_name = args.tool
    tool_cls = TOOLS[tool_name]
    tool_kwargs = vars(args).copy()
    tool_kwargs.pop("tool")

    want_json = tool_kwargs.pop("json", False)
    output_file = tool_kwargs.pop("output", None)

    if want_json:
        import utils.output
        utils.output.QUIET = True

    print_banner()

    if not want_json:
        section(f"Running: {HELP_DESCRIPTIONS.get(tool_name, tool_cls.description)}")

    try:
        result = tool_cls.run(**tool_kwargs)
        if want_json:
            import json
            output = json.dumps(result, indent=2, default=str)
            print(output)
        if output_file:
            import json
            with open(output_file, "w") as f:
                json.dump(result, f, indent=2, default=str)
            if not want_json:
                print(f"\n[+] Output written to {output_file}")
        if not want_json:
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
