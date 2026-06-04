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
from tools.smtp_enum import SMTPEnum
from tools.email_finder import EmailFinder
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
    "smtp": SMTPEnum,
    "email-finder": EmailFinder,
    "email-recon": EmailRecon,
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
    "smtp": "SMTP server enumeration and email validation",
    "email-finder": "Find email addresses from domain (scraping, pattern guessing, search engines)",
    "email-recon": "Full email intelligence (breach check, social media, search footprint, Gravatar)",
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
}
