from tools.port_scanner import PortScanner
from tools.subdomain_finder import SubdomainFinder
from tools.dir_bruteforcer import DirBruteforcer
from tools.dns_recon import DNSRecon
from tools.whois_lookup import WhoisLookup
from tools.header_analyzer import HeaderAnalyzer
from tools.ssl_checker import SSLChecker
from tools.wayback_scraper import WaybackScraper
from tools.email_extractor import EmailExtractor
from tools.link_extractor import LinkExtractor
from tools.tech_detector import TechDetector
from tools.metadata_extractor import MetadataExtractor
from tools.web_crawler import WebCrawler
from tools.cve_search import CVESearch
from tools.ip_geolocator import IPGeolocator
from tools.url_fuzzer import AdvancedURLFuzzer as URLFuzzer
from tools.google_dorker import GoogleDorker
from tools.username_search import UsernameSearch
from tools.cert_search import CertSearch
from tools.waf_detector import WAFDetector
from tools.reverse_ip import ReverseIP
from tools.github_osint import GitHubOSINT
from tools.breach_checker import BreachChecker
from tools.social_linker import SocialLinker
from tools.js_scraper import JSScraper
from tools.form_analyzer import AdvancedFormAnalyzer as FormAnalyzer
from tools.asn_lookup import ASNLookup
from tools.httpmethods import AdvancedHTTPMethodsScanner as HTTPMethodsScanner
from tools.cors_checker import AdvancedCORSChecker as CORSChecker
from tools.sqli_scanner import AdvancedSQLIScanner as SQLIScanner
from tools.xss_scanner import AdvancedXSSScanner as XSSScanner
from tools.admin_finder import AdvancedAdminFinder as AdminFinder
from tools.openredirect import AdvancedOpenRedirectChecker as OpenRedirectChecker
from tools.cloud_enum import CloudEnum
from tools.crlf_injection import CRLFInjection
from tools.command_injection import CommandInjection
from tools.smtp_enum import SMTPEnum
from tools.email_finder import EmailFinder
from tools.email_security import EmailSecurity
from tools.email_recon import EmailRecon
from tools.phone_info import PhoneInfo
from tools.phone_social import PhoneSocial
from tools.tor_check import TorCheck
from tools.pastewatch import PasteWatch
from tools.deep_search import DeepSearch
from tools.mac_address_lookup import MACLookup
from tools.favicon_hash import FaviconHash
from tools.redirect_tracker import RedirectTracker
from tools.robots_analyzer import RobotsAnalyzer
from tools.shodan_search import ShodanSearch
from tools.malware_hunter import MalwareHunter
from tools.c2_hunter import C2Hunter
from tools.phish_hunter import PhishHunter
from tools.telegram_osint import TelegramOSINT
from tools.reddit_osint import RedditOSINT
from tools.social_recon import SocialRecon
from tools.auto_recon import AutoRecon
from tools.jwt_toolkit import JwtToolkit
from tools.ssrf_scanner import SsrfScanner
from tools.takeover_checker import TakeoverChecker
from tools.login_brute import LoginBrute
from tools.report_gen import ReportGen
from tools.graphql_scanner import GraphQLScanner
from tools.api_fuzzer import APIFuzzer
from tools.smuggler import Smuggler
from tools.ws_tester import WebSocketTester
from tools.race_condition import RaceCondition
from tools.ssti_scanner import SSTIScanner
from tools.xxe_scanner import XXEScanner
from tools.network_scan import NetworkScan
from tools.snmp_enum import SNMPEnum
from tools.smb_enum import SMBEnum
from tools.nfs_enum import NFSEnum
from tools.ldap_scanner import LDAPScanner
from tools.rpc_enum import RPCEnum
from tools.cred_spray import CredSpray
from tools.default_creds import DefaultCreds
from tools.password_analyze import PasswordAnalyze
from tools.hash_id import HashID
from tools.host_header_injection import HostHeaderInjection
from tools.insecure_deserialization import InsecureDeserialization
from tools.lfi_rfi_scanner import LFIRFIScanner
from tools.nosql_injection import NoSQLInjection
from tools.prototype_pollution import PrototypePollution
from tools.web_screenshot import WebScreenshot
from tools.wordlist_generator import WordlistGenerator
from tools.aws_enum import AWSEnum
from tools.k8s_audit import K8sAudit
from tools.container_scan import ContainerScan
from tools.cloud_metadata import CloudMetadata
from tools.project_db import ProjectDB
from tools.ai_chat import AIChat

TOOLS = {
    "port-scan": PortScanner,
    "subdomain": SubdomainFinder,
    "dir-bust": DirBruteforcer,
    "dns": DNSRecon,
    "whois": WhoisLookup,
    "headers": HeaderAnalyzer,
    "ssl": SSLChecker,
    "wayback": WaybackScraper,
    "email": EmailExtractor,
    "links": LinkExtractor,
    "tech": TechDetector,
    "metadata": MetadataExtractor,
    "crawl": WebCrawler,
    "cve": CVESearch,
    "geoip": IPGeolocator,
    "fuzz": URLFuzzer,
    "dork": GoogleDorker,
    "username": UsernameSearch,
    "certsearch": CertSearch,
    "waf": WAFDetector,
    "reverseip": ReverseIP,
    "github": GitHubOSINT,
    "breach": BreachChecker,
    "sociallinks": SocialLinker,
    "js": JSScraper,
    "forms": FormAnalyzer,
    "asn": ASNLookup,
    "httpmethods": HTTPMethodsScanner,
    "cors": CORSChecker,
    "sqli": SQLIScanner,
    "xss": XSSScanner,
    "admin": AdminFinder,
    "openredirect": OpenRedirectChecker,
    "cloud": CloudEnum,
    "cmd-injection": CommandInjection,
    "crlf-injection": CRLFInjection,
    "smtp": SMTPEnum,
    "email-finder": EmailFinder,
    "email-recon": EmailRecon,
    "email-security": EmailSecurity,
    "phone-info": PhoneInfo,
    "phone-social": PhoneSocial,
    "tor-check": TorCheck,
    "pastewatch": PasteWatch,
    "deep-search": DeepSearch,
    "mac-address": MACLookup,
    "favicon": FaviconHash,
    "redirects": RedirectTracker,
    "robots": RobotsAnalyzer,
    "shodan": ShodanSearch,
    "malware-hunt": MalwareHunter,
    "c2-hunt": C2Hunter,
    "phish-hunt": PhishHunter,
    "telegram-osint": TelegramOSINT,
    "reddit-osint": RedditOSINT,
    "social-recon": SocialRecon,
    "auto-recon": AutoRecon,

    "jwt": JwtToolkit,
    "ssrf": SsrfScanner,
    "takeover": TakeoverChecker,
    "brute": LoginBrute,
    "report": ReportGen,
    "graphql": GraphQLScanner,
    "api-fuzz": APIFuzzer,
    "smuggle": Smuggler,
    "ws": WebSocketTester,
    "race": RaceCondition,
    "lfi-rfi": LFIRFIScanner,
    "ssti": SSTIScanner,
    "nosqli": NoSQLInjection,
    "xxe": XXEScanner,
    "net-scan": NetworkScan,
    "snmp": SNMPEnum,
    "smb": SMBEnum,
    "nfs": NFSEnum,
    "ldap": LDAPScanner,
    "rpc": RPCEnum,
    "cred-spray": CredSpray,
    "default-creds": DefaultCreds,
    "deserialize": InsecureDeserialization,
    "pass-analyze": PasswordAnalyze,
    "hash-id": HashID,
    "host-header-injection": HostHeaderInjection,
    "aws-enum": AWSEnum,
    "k8s": K8sAudit,
    "container": ContainerScan,
    "cloud-meta": CloudMetadata,
    "project": ProjectDB,
    "proto-pollution": PrototypePollution,
    "screenshot": WebScreenshot,
    "wordlist": WordlistGenerator,
    "ai-chat": AIChat,
}

HELP_DESCRIPTIONS = {
    "port-scan": "Scan open ports on a target host",
    "subdomain": "Discover subdomains of a target domain",
    "dir-bust": "Brute force directories and files on a web server",
    "dns": "DNS enumeration and reconnaissance",
    "whois": "WHOIS lookup for domain or IP addresses",
    "headers": "Analyze HTTP security headers",
    "ssl": "Check SSL/TLS certificate information",
    "wayback": "Fetch historical URLs from Wayback Machine",
    "email": "Extract email addresses from web pages",
    "links": "Extract and analyze links from a web page",
    "tech": "Detect technologies used on a website",
    "metadata": "Extract metadata from files (images, PDFs, documents)",
    "crawl": "Crawl a website to enumerate URLs and structure",
    "cve": "Search for known vulnerabilities (CVEs)",
    "geoip": "Geolocate an IP address or domain",
    "fuzz": "Advanced URL and parameter fuzzing (12+ vulnerability categories)",
    "dork": "Generate and organize Google dork queries",
    "username": "Search for a username across 100+ social platforms",
    "certsearch": "Search Certificate Transparency logs for subdomains",
    "waf": "Detect Web Application Firewalls and reverse proxies",
    "reverseip": "Find domains hosted on the same IP address",
    "github": "GitHub user, repository, and code OSINT",
    "breach": "Check email/password against known data breaches",
    "sociallinks": "Extract social media links from a website",
    "js": "Extract API endpoints and secrets from JavaScript",
    "forms": "Advanced form security analysis (CSRF, hidden fields, credentials leak, API key exposure)",
    "asn": "Look up ASN, network ranges, and ISP information",
    "httpmethods": "Advanced HTTP method enum (WebDAV, override headers, per-path, PUT upload test)",
    "cors": "Advanced CORS scanner (preflight, credential leak, wildcard, origin reflection, 40+ tests)",
    "sqli": "Advanced SQLi scanner (error, boolean, time, WAF bypass, second-order, stacked, 200+ payloads)",
    "xss": "Advanced XSS scanner (context-aware, polyglots, DOM, stored, mXSS, CSP analysis, 150+ payloads)",
    "admin": "Advanced admin finder (CMS detection, fuzzy matching, login form analysis, 250+ paths)",
    "openredirect": "Advanced open redirect scanner (validation bypass, JS/DOM discovery, CRLF, param pollution)",
    "cloud": "Enumerate cloud storage and hosting services",
    "cmd-injection": "Command injection vulnerability scanner with time-based and blind detection",
    "crlf-injection": "CRLF (HTTP Response Splitting) injection scanner",
    "smtp": "SMTP server enumeration and email validation",
    "email-finder": "Find email addresses from domain (scraping, pattern guessing, search engines)",
    "email-recon": "Full email intelligence (breach check, social media, search footprint, Gravatar)",
    "email-security": "Email security analyzer: SPF, DKIM, DMARC, MX, and security scoring",
    "phone-info": "Phone number intelligence (country, carrier, line type, location, reputation)",
    "phone-social": "Find social media and messaging accounts linked to a phone number",
    "tor-check": "Tor/dark web reconnaissance (.onion mirrors, exit nodes, dark web search)",
    "pastewatch": "Pastebin and code snippet monitoring (paste search, leak detection, recent monitoring)",
    "deep-search": "Deep internet search (cross-engine, file types, code repos, people search, dork generator)",
    "mac-address": "Look up MAC address vendor/OUI information",
    "favicon": "Calculate favicon hash (mmh3) for Shodan/device identification",
    "redirects": "Trace and analyze HTTP redirect chains",
    "robots": "Analyze robots.txt and sitemap.xml for recon",
    "shodan": "Search Shodan.io for devices, services, and open ports",
    "malware-hunt": "Multi-source malware URL & IOC hunter: URLhaus, ThreatFox, MalwareBazaar, Feodo, URLScan",
    "c2-hunt": "C2 infrastructure reconnaissance: blocklists, SSL fingerprints, panel discovery, ThreatFox",
    "phish-hunt": "Phishing infrastructure hunter: URLScan phishing search, cert monitoring, kit discovery, dorking",
    "telegram-osint": "Telegram OSINT: channel/group intelligence, message analysis, forward tracking, activity patterns",
    "reddit-osint": "Reddit OSINT: user profile analysis, subreddit recon, content tracking, cross-post detection",
    "social-recon": "Cross-platform social media recon: 60+ platforms, profile discovery, metadata extraction, correlation",
    "auto-recon": "Autonomous recon orchestration with AI-driven decision making and chained tool execution",
    "jwt": "JWT analysis and attack toolkit (decode, crack, algorithm confusion, KID injection)",
    "ssrf": "Blind and reflected SSRF detection with out-of-band verification and cloud metadata probing",
    "takeover": "Subdomain takeover detection (AWS, Azure, GitHub, Heroku, Netlify, 20+ services)",
    "brute": "HTTP form/basic/digest authentication brute forcer with auto field detection",
    "report": "Generate HTML/JSON/text pentest reports from JSON output files",
    "graphql": "GraphQL security scanner: introspection, batching attacks, query depth, auth bypass",
    "api-fuzz": "Advanced REST/GraphQL API fuzzer: header injection, param pollution, rate limit testing",
    "smuggle": "HTTP request smuggler: CL.TE, TE.CL, TE.TE detection and exploitation",
    "ws": "WebSocket security tester: origin bypass, message fuzzing, DoS resistance",
    "race": "Race condition tester: concurrent request racing for discount, OTP, rate-limit bypass",
    "lfi-rfi": "Local File Inclusion and Remote File Inclusion vulnerability scanner",
    "ssti": "SSTI scanner: Jinja2, Twig, Freemarker, Velocity, Jade, ERB, Tornado, Mako, Smarty",
    "nosqli": "NoSQL injection vulnerability scanner for MongoDB and other NoSQL databases",
    "xxe": "XXE scanner: file read, SSRF, blind exfiltration, 9 DOCTYPE variants including XInclude and SVG",
    "net-scan": "Network scanner: ARP discovery, ping sweep, OS fingerprinting, port scanning",
    "snmp": "SNMP enumerator: community string brute force, MIB tree walk, interface/user extraction",
    "smb": "SMB enumerator: share listing, null session, OS version, RID cycle user enum",
    "nfs": "NFS enumerator: export listing, mount checking, permission analysis, rpcbind query",
    "ldap": "LDAP scanner: anonymous bind, attribute discovery, user/group dump, DN enumeration",
    "rpc": "RPC enumerator: endpoint mapper dump, service discovery, unusual port detection",
    "cred-spray": "Credential sprayer: password spraying with anti-lockout detection and cooldown",
    "default-creds": "Default credential checker: 500+ known device/service defaults",
    "deserialize": "Insecure deserialization scanner for PHP, Python, Java, Ruby, .NET",
    "pass-analyze": "Password strength analyzer: entropy, patterns, crack time estimation",
    "hash-id": "Hash identifier and cracker: 50+ hash types, wordlist/rainbow table cracking",
    "host-header-injection": "Host header injection scanner: cache poisoning, password reset poisoning, SSRF",
    "aws-enum": "AWS enumeration: IAM/S3/EC2/STS checks, bucket discovery, metadata probing",
    "k8s": "Kubernetes security audit: RBAC, dashboard, etcd, kubelet, API server, pod/secret exposure",
    "container": "Container security scanner: Docker API, breakout tests, image vulnerability check",
    "cloud-meta": "Cloud metadata exposure scanner: AWS, Azure, GCP, Alibaba, DigitalOcean, OpenStack",
    "project": "Project database: SQLite-backed target/project management with scan comparison",
    "proto-pollution": "Server-side prototype pollution scanner for Node.js applications",
    "screenshot": "Take full-page screenshots of websites using Playwright",
    "wordlist": "Custom wordlist generator from target website content and AI patterns",
    "ai-chat": "Interactive AI chat that runs recon/scanning tools autonomously using natural language",
}
