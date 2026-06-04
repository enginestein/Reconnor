# Hacking Suite Wiki


## Overview

A comprehensive, custom-built suite of 47 security research and OSINT (Open Source Intelligence) tools for educational purposes. All tools are standalone Python scripts with no external tool wrappers.

### Quick Start

```bash
# List all available tools
python3 main.py

# Get help for a specific tool
python3 main.py <tool> --help

# Example: scan ports
python3 main.py port-scan example.com

# Example: find subdomains
python3 main.py subdomain example.com
```

### Dependencies

```bash
pip install requests beautifulsoup4 colorama Pillow dnspython
```

---

## AI-Assisted Mode (Ollama)

11 tools support local LLM integration via [Ollama](https://ollama.ai) for smarter analysis and payload generation.

```bash
# First: install Ollama and pull a model
# Then: add --ollama-model to any supported tool
python3 main.py admin example.com --ollama-model llama3.2
python3 main.py dir-bust example.com --ollama-model llama3.2
python3 main.py fuzz example.com/page?id=1 --ollama-model llama3.2
python3 main.py redirects example.com --ollama-model llama3.2
python3 main.py robots example.com --ollama-model llama3.2
python3 main.py shodan example.com --ollama-model llama3.2
```

See [tools/ollama-integration.md](tools/ollama-integration.md) for details.

---

## Tool Categories

### 1. Reconnaissance & Discovery
Tools to gather information about a target.

| Tool | Description |
|------|-------------|
| [subdomain](tools/subdomain.md) | Discover subdomains via brute force |
| [dns](tools/dns.md) | DNS enumeration and record discovery |
| [certsearch](tools/certsearch.md) | Certificate Transparency log search |
| [reverseip](tools/reverseip.md) | Find domains on same IP |
| [whois](tools/whois.md) | WHOIS domain/IP lookups |
| [asn](tools/asn.md) | ASN and network range lookup |
| [geoip](tools/geoip.md) | IP geolocation |
| [cve](tools/cve.md) | CVE vulnerability search |
| [github](tools/github.md) | GitHub OSINT (users, repos, code) |
| [username](tools/username.md) | Username search across 100+ platforms |
| [breach](tools/breach.md) | Data breach checker |
| [cloud](tools/cloud.md) | Cloud service enumeration |
| [smtp](tools/smtp.md) | SMTP server enumeration |
| [shodan](tools/shodan.md) | Shodan.io device and service search |
| [mac-address](tools/mac-address.md) | MAC address vendor/OUI lookup |

### 2. Website Analysis
Tools to analyze websites and web technologies.

| Tool | Description |
|------|-------------|
| [tech](tools/tech.md) | Detect web technologies (CMS, frameworks, CDN, etc.) |
| [headers](tools/headers.md) | HTTP security header analysis |
| [ssl](tools/ssl.md) | SSL/TLS certificate inspection |
| [waf](tools/waf.md) | WAF detection (30+ signatures) |
| [crawl](tools/crawl.md) | Recursive website crawler |
| [links](tools/links.md) | Link extraction and health check |
| [email](tools/email.md) | Email address extraction |
| [sociallinks](tools/sociallinks.md) | Social media link extraction |
| [forms](tools/forms.md) | HTML form security analysis |
| [js](tools/js.md) | JavaScript endpoint/secret extraction |
| [wayback](tools/wayback.md) | Wayback Machine historical URLs |
| [dork](tools/dork.md) | Google dork query generator |
| [robots](tools/robots.md) | Robots.txt and sitemap.xml recon analyzer |
| [favicon](tools/favicon.md) | Favicon hash calculator for Shodan |
| [redirects](tools/redirects.md) | HTTP redirect chain analyzer |

### 3. Web Security Testing
Tools to identify security vulnerabilities.

| Tool | Description |
|------|-------------|
| [port-scan](tools/port-scan.md) | TCP port scanner with banner grab |
| [dir-bust](tools/dir-bust.md) | Directory/file brute force |
| [fuzz](tools/fuzz.md) | URL and parameter fuzzing |
| [httpmethods](tools/httpmethods.md) | HTTP method enumeration |
| [cors](tools/cors.md) | CORS misconfiguration checker |
| [sqli](tools/sqli.md) | SQL injection scanner |
| [xss](tools/xss.md) | XSS vulnerability scanner |
| [admin](tools/admin.md) | Admin panel finder |
| [openredirect](tools/openredirect.md) | Open redirect checker |

### 4. File & Metadata Analysis

| Tool | Description |
|------|-------------|
| [metadata](tools/metadata.md) | File metadata/EXIF extraction |
| [link](tools/links.md) | Link analysis |

---

## Tool Reference

### admin
**Find admin panels and login pages.**  
Scans 100+ common admin panel paths and checks for login indicators.

```
python3 main.py admin https://example.com
```

### asn
**ASN, network range, and ISP information lookup.**  
Uses ip-api.com and bgpview.io to resolve ASN details.

```
python3 main.py asn 8.8.8.8
python3 main.py asn AS15169
python3 main.py asn example.com
```

### breach
**Data breach checker.**  
Check emails against the HIBP API and passwords against known breaches.

```
python3 main.py breach email@example.com
python3 main.py breach mypassword --type password
```

### certsearch
**Certificate Transparency log search.**  
Queries crt.sh and CertSpotter for SSL certificate records to discover subdomains.

```
python3 main.py certsearch example.com
python3 main.py certsearch example.com --all
```

### cloud
**Cloud service enumeration.**  
Tests bucket names across AWS S3, Azure Blob, GCP Storage, Firebase, Heroku, Netlify, Vercel, and 10+ other cloud platforms.

```
python3 main.py cloud example.com
```

### cors
**CORS misconfiguration checker.**  
Tests 10+ origin variations (null, subdomain, different domain, prefix, suffix, etc.) to find overly permissive CORS policies.

```
python3 main.py cors https://api.example.com
```

### crawl
**Recursive web crawler.**  
Crawls a website up to a specified depth, building a URL tree.

```
python3 main.py crawl https://example.com --depth 3 --max-urls 200
```

### cve
**CVE vulnerability search.**  
Queries CIRCL and NVD databases for known vulnerabilities matching a keyword.

```
python3 main.py cve log4j
python3 main.py cve wordpress --limit 50
```

### dir-bust
**Directory and file brute force.**  
Tests 1000+ common web paths. Optionally appends common extensions (.php, .asp, etc.).

```
python3 main.py dir-bust https://example.com
python3 main.py dir-bust https://example.com --extensions
python3 main.py dir-bust https://example.com -w /path/to/wordlist.txt
```

### dns
**DNS enumeration.**  
Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records. Optionally attempts zone transfer.

```
python3 main.py dns example.com
python3 main.py dns example.com --zone-transfer
```

### dork
**Google dork generator.**  
Generates organized Google search queries across 12 categories (Admin panels, Logs, Config files, Database, etc.).

```
python3 main.py dork
python3 main.py dork --domain example.com
python3 main.py dork --category "Login"
```

### email
**Email address extractor.**  
Extracts email addresses from web pages using regex patterns.

```
python3 main.py email https://example.com
python3 main.py email https://example.com --crawl --depth 2
```

### forms
**HTML form security analysis.**  
Analyzes forms for password fields over HTTP, missing CSRF tokens, autocomplete enabled, and more.

```
python3 main.py forms https://example.com/login
```

### favicon
**Favicon hash calculator.**  
Downloads a site's favicon and computes its mmh3 hash for Shodan-based device identification.

```
python3 main.py favicon example.com
```

### fuzz
**URL fuzzing tool.**  
Tests URL parameters with fuzz payloads including XSS, SQLi, path traversal, and more.

```
python3 main.py fuzz https://example.com/page?id=1
python3 main.py fuzz https://example.com/page --params id,page,user
```

### geoip
**IP geolocation.**  
Resolves IP address or domain to geographic location with map visualization.

```
python3 main.py geoip 8.8.8.8
python3 main.py geoip example.com
python3 main.py geoip me
```

### github
**GitHub OSINT.**  
Query GitHub for user profiles, repository info, or code search.

```
python3 main.py github john --mode user
python3 main.py github tensorflow --mode repo
python3 main.py github "api key" --mode search
```

### headers
**HTTP security header analyzer.**  
Checks for 20+ security headers and rates security posture.

```
python3 main.py headers example.com
```

### httpmethods
**HTTP method enumeration.**  
Tests 9 HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT) and flags dangerous ones.

```
python3 main.py httpmethods https://example.com
```

### js
**JavaScript scraper.**  
Extracts API endpoints, routes, secrets, and hardcoded strings from JavaScript files.

```
python3 main.py js https://example.com
python3 main.py js https://example.com --threads 30
```

### links
**Link extractor.**  
Extracts all links from a web page and optionally checks their HTTP status.

```
python3 main.py links https://example.com
python3 main.py links https://example.com --check
```

### mac-address
**MAC address vendor lookup.**  
Looks up the vendor/OUI for a MAC address using macvendors.com API and a local OUI database.

```
python3 main.py mac-address 00:11:22:33:44:55
```

### metadata
**Metadata extractor.**  
Extracts metadata/EXIF from images, PDFs, office documents, and audio files.

```
python3 main.py metadata /path/to/file.jpg
python3 main.py metadata /path/to/directory/
```

### openredirect
**Open redirect checker.**  
Tests URL parameters for open redirect vulnerabilities using 12 payload types.

```
python3 main.py openredirect https://example.com/page?url=http://evil.com
python3 main.py openredirect https://example.com
```

### port-scan
**TCP port scanner.**  
Scans common ports with banner grabbing and multi-threading.

```
python3 main.py port-scan example.com
python3 main.py port-scan 192.168.1.1 --ports 1-1000
python3 main.py port-scan example.com --ports 22,80,443,3306
```

### redirects
**Redirect chain tracker.**  
Traces the full HTTP redirect chain with security analysis, detecting loops, HTTPS→HTTP downgrades, and open redirects.

```
python3 main.py redirects example.com
python3 main.py redirects example.com --ollama-model llama3.2
```

### reverseip
**Reverse IP lookup.**  
Finds all domains hosted on the same IP address using multiple sources.

```
python3 main.py reverseip example.com
python3 main.py reverseip 8.8.8.8
```

### robots
**Robots.txt & sitemap analyzer.**  
Fetches and analyzes robots.txt and sitemap.xml for hidden resources, disallowed paths, and recon opportunities.

```
python3 main.py robots example.com
python3 main.py robots example.com --ollama-model llama3.2
```

### shodan
**Shodan.io search.**  
Searches Shodan for devices, services, and open ports. Supports host lookup and search query modes.

```
python3 main.py shodan example.com
python3 main.py shodan --query "apache 2.4.49 country:US"
python3 main.py shodan example.com --ollama-model llama3.2
```

### smtp
**SMTP enumeration.**  
Resolves MX records, connects to SMTP servers, enumerates supported commands, and checks for open relay.

```
python3 main.py smtp example.com
python3 main.py smtp example.com --port 587
```

### sociallinks
**Social media link extractor.**  
Finds links to 40+ social media platforms in a website's HTML.

```
python3 main.py sociallinks https://example.com
```

### sqli
**SQL injection scanner.**  
Tests URL parameters with 14 SQL injection payloads and checks responses for error patterns.

```
python3 main.py sqli https://example.com/page?id=1
```

### ssl
**SSL/TLS checker.**  
Inspects SSL certificate details including issuer, validity, SANs, and cipher info.

```
python3 main.py ssl example.com
python3 main.py ssl example.com --port 8443
```

### subdomain
**Subdomain finder.**  
Brute-forces subdomains using a built-in list of 1000+ common subdomains.

```
python3 main.py subdomain example.com
python3 main.py subdomain example.com -w /path/to/wordlist.txt
```

### tech
**Technology detector.**  
Identifies 100+ web technologies including CMS, frameworks, CDN, WAF, analytics, JS libraries, and databases.

```
python3 main.py tech example.com
```

### username
**Username search.**  
Searches for a username across 100+ social media and web platforms (sherlock-style).

```
python3 main.py username john
python3 main.py username john --platforms github,twitter,reddit
```

### waf
**WAF detector.**  
Detects 30+ Web Application Firewalls and reverse proxies by analyzing response headers/cookies and probing with malicious payloads.

```
python3 main.py waf https://example.com
```

### wayback
**Wayback Machine scraper.**  
Fetches historical snapshots of a domain from the Wayback Machine.

```
python3 main.py wayback example.com
python3 main.py wayback example.com --limit 200
```

### whois
**WHOIS lookup.**  
Performs WHOIS queries for domain registration or IP address information.

```
python3 main.py whois example.com
python3 main.py whois 8.8.8.8
```

### xss
**XSS scanner.**  
Tests URL parameters and forms with 12 XSS payloads and checks for reflection in responses.

```
python3 main.py xss https://example.com/page?q=test
```

---

### Tool Interface

Every tool follows the same interface:

```python
class ToolName:
    name = "tool-name"  # CLI subcommand name
    description = "Short description"

    @staticmethod
    def run(target, **kwargs):
        # Perform operations
        # Print output via utils.output helpers
        return {"result": data}
```

### Output Helpers

Located in `utils/output.py`, these provide colorized terminal output:

| Function | Color | Usage |
|----------|-------|-------|
| `section(title)` | Cyan | Section headers |
| `info(text)` | Blue | Informational messages |
| `success(text)` | Green | Positive findings |
| `warning(text)` | Yellow | Warnings/flagging |
| `error(text)` | Red | Errors |
| `result(label, value)` | White/Yellow | Key-value results |
| `table(headers, rows)` | White | Tabular data |

---

## Legal Disclaimer

These tools are provided for **educational purposes only**. Unauthorized scanning, probing, or attacking of systems you do not own or have explicit written permission to test is **illegal** and **unethical**. Users are solely responsible for complying with all applicable laws.
