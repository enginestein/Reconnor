```
                             ▗▄▄▖ ▗▄▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▖  ▗▖ ▗▄▖ ▗▄▄▖ 
                             ▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌ ▐▌▐▌ ▐▌
                             ▐▛▀▚▖▐▛▀▀▘▐▌   ▐▌ ▐▌▐▌ ▝▜▌▐▌ ▝▜▌▐▌ ▐▌▐▛▀▚▖
                             ▐▌ ▐▌▐▙▄▄▖▝▚▄▄▖▝▚▄▞▘▐▌  ▐▌▐▌  ▐▌▝▚▄▞▘▐▌ ▐▌

```          

> **WIP**

## Overview

A comprehensive, custom-built suite of **92 security research and OSINT (Open Source Intelligence) tools** for educational purposes. All tools are standalone Python scripts with no external tool wrappers.

> **Optional external tools** (nmap, amass, ffuf, etc.) can be enabled per-tool via `--nmap`/`--ext` flags.  
> Run `reconnor-setup` to auto-install all system dependencies, or `pip install .[ext]` for pip-based tools.

---

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

### Installation

```bash
# Quick install (core Python deps only)
pip install -r requirements.txt

# Full install (includes pip-based external tools like sublist3r, wafw00f)
pip install .[ext]

# Install all system-level dependencies (nmap, amass, ffuf, etc.)
reconnor-setup
```

---

## AI-Assisted Mode

The suite supports **multi-provider LLM integration** for smarter analysis and payload generation.

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| [Ollama](https://ollama.ai) (local) | `RECONNOR_LLM=ollama` | `llama3.2` |
| [OpenAI](https://openai.com) | `OPENAI_API_KEY` | `gpt-4o-mini` |
| [Anthropic](https://anthropic.com) | `ANTHROPIC_API_KEY` | `claude-3-haiku-20240307` |
| [Gemini](https://makersuite.google.com) | `GEMINI_API_KEY` | `gemini-1.5-flash` |

### Per-Tool AI Usage (Ollama models)
```bash
python3 main.py fuzz https://example.com --ollama-model llama3.2
python3 main.py forms https://example.com --ollama-model llama3.2
python3 main.py admin https://example.com --ollama-model llama3.2
python3 main.py openredirect https://example.com --ollama-model llama3.2
```

Tools with AI support: `fuzz`, `forms`, `admin`, `openredirect`, `sqli`, `xss`, `dir-bust`, `redirects`, `robots`, `shodan`, `js`, `lfi-rfi`, `cmd-injection`, `nosqli`, `host-header-injection`, `crlf-injection`, `proto-pollution`, `deserialize`, `wordlist`, `auto-recon`, `ai-chat`

### Cloud LLMs
```bash
export OPENAI_API_KEY="sk-..."
python3 main.py auto-recon example.com --use-ai --llm-provider openai

export ANTHROPIC_API_KEY="sk-ant-..."
python3 main.py auto-recon example.com --use-ai --llm-provider anthropic

python3 main.py ai-chat --provider openai --model gpt-4o-mini
```

See [wiki/ollama-integration.md](wiki/ollama-integration.md) for details.

---

## Tool Categories

### 1. Reconnaissance & Discovery
Tools to gather information about a target.

| Tool | Description |
|------|-------------|
| [subdomain](wiki/subdomain.md) | Discover subdomains via brute force |
| [dns](wiki/dns.md) | DNS enumeration and record discovery |
| [certsearch](wiki/certsearch.md) | Certificate Transparency log search |
| [reverseip](wiki/reverseip.md) | Find domains on same IP |
| [whois](wiki/whois.md) | WHOIS domain/IP lookups |
| [asn](wiki/asn.md) | ASN and network range lookup |
| [geoip](wiki/geoip.md) | IP geolocation |
| [cve](wiki/cve.md) | CVE vulnerability search |
| [github](wiki/github.md) | GitHub OSINT (users, repos, code) |
| [username](wiki/username.md) | Username search across 100+ platforms |
| [breach](wiki/breach.md) | Data breach checker |
| [cloud](wiki/cloud.md) | Cloud service enumeration |
| [smtp](wiki/smtp.md) | SMTP server enumeration |
| [shodan](wiki/shodan.md) | Shodan.io device and service search |
| [mac-address](wiki/mac-address.md) | MAC address vendor/OUI lookup |
| [deep-search](wiki/deep-search.md) | Cross-engine deep internet search |
| [email-finder](wiki/email-finder.md) | Find email addresses from a domain |
| [email-recon](wiki/email-recon.md) | Full email intelligence and breach check |
| [pastewatch](wiki/pastewatch.md) | Pastebin monitoring and leak detection |
| [phone-info](wiki/phone-info.md) | Phone number intelligence and carrier lookup |
| [phone-social](wiki/phone-social.md) | Find social accounts linked to a phone number |
| [tor-check](wiki/tor-check.md) | Tor/dark web reconnaissance |
| [email-security](wiki/email-security.md) | Email security analyzer (SPF, DKIM, DMARC, MX, security scoring) |
| [wordlist](wiki/wordlist.md) | Custom wordlist generator from website content and AI patterns |

### 1a. OSINT & Threat Intelligence
Specialized OSINT tools for tracking threats, phishing, malware, and social platforms.

| Tool | Description |
|------|-------------|
| [malware-hunt](wiki/malware-hunt.md) | Multi-source malware URL & IOC hunter (URLhaus, ThreatFox, MalwareBazaar, Feodo) |
| [c2-hunt](wiki/c2-hunt.md) | C2 infrastructure reconnaissance (blocklists, SSL fingerprints, panel discovery) |
| [phish-hunt](wiki/phish-hunt.md) | Phishing infrastructure hunter (URLScan, cert monitoring, kit discovery, dorking) |
| [telegram-osint](wiki/telegram-osint.md) | Telegram OSINT (channel/group intelligence, message analysis, forward tracking) |
| [reddit-osint](wiki/reddit-osint.md) | Reddit OSINT (user profile analysis, subreddit recon, content tracking) |
| [social-recon](wiki/social-recon.md) | Cross-platform social media recon (60+ platforms, profile discovery, correlation) |

### 1b. AI & Autonomous Tools
Intelligent agents and interactive AI helpers.

| Tool | Description |
|------|-------------|
| [auto-recon](#auto-recon) | Autonomous recon orchestrator with AI-driven decision making |
| [ai-chat](wiki/ai-chat.md) | Autonomous AI assistant that runs 92 tools via natural language |

### 1c. Advanced Security Testing
Specialized security testing tools.

| Tool | Description |
|------|-------------|
| [jwt](#jwt) | JWT analysis and attack toolkit (decode, crack, alg confusion, KID) |
| [ssrf](#ssrf) | Blind and reflected SSRF detection with OOB verification |
| [takeover](#takeover) | Subdomain takeover detection (20+ cloud services) |
| [brute](#brute) | HTTP form/basic/digest authentication brute forcer |
| [graphql](wiki/graphql.md) | GraphQL security scanner (introspection, batching, query depth, auth bypass) |
| [api-fuzz](wiki/api-fuzz.md) | Advanced REST/GraphQL API fuzzer (header injection, param pollution, rate limits) |
| [smuggle](wiki/smuggle.md) | HTTP request smuggler (CL.TE, TE.CL, TE.TE detection) |
| [ws](wiki/ws.md) | WebSocket security tester (origin bypass, message fuzzing, DoS resistance) |
| [race](wiki/race.md) | Race condition tester (concurrent request racing for OTP/discount bypass) |
| [ssti](wiki/ssti.md) | SSTI scanner (Jinja2, Twig, Freemarker, Velocity, Jade, ERB, Tornado, Mako, Smarty) |
| [xxe](wiki/xxe.md) | XXE scanner (file read, SSRF, blind exfiltration, 9 DOCTYPE variants) |
| [report](#report) | Generate HTML/JSON/text pentest reports from JSON output |

### 2. Website Analysis
Tools to analyze websites and web technologies.

| Tool | Description |
|------|-------------|
| [tech](wiki/tech.md) | Detect web technologies (CMS, frameworks, CDN, etc.) |
| [headers](wiki/headers.md) | HTTP security header analysis |
| [ssl](wiki/ssl.md) | SSL/TLS certificate inspection |
| [waf](wiki/waf.md) | WAF detection (30+ signatures) |
| [crawl](wiki/crawl.md) | Recursive website crawler |
| [links](wiki/links.md) | Link extraction and health check |
| [email](wiki/email.md) | Email address extraction |
| [sociallinks](wiki/sociallinks.md) | Social media link extraction |
| [forms](wiki/forms.md) | HTML form security analysis |
| [js](wiki/js.md) | JavaScript endpoint/secret extraction |
| [wayback](wiki/wayback.md) | Wayback Machine historical URLs |
| [dork](wiki/dork.md) | Google dork query generator |
| [robots](wiki/robots.md) | Robots.txt and sitemap.xml recon analyzer |
| [favicon](wiki/favicon.md) | Favicon hash calculator for Shodan |
| [redirects](wiki/redirects.md) | HTTP redirect chain analyzer |
| [screenshot](wiki/screenshot.md) | Full-page website screenshots using Playwright |

### 3. Web Security Testing
Tools to identify security vulnerabilities.

| Tool | Description |
|------|-------------|
| [port-scan](wiki/port-scan.md) | TCP port scanner with banner grab |
| [dir-bust](wiki/dir-bust.md) | Directory/file brute force |
| [fuzz](wiki/fuzz.md) | URL and parameter fuzzing |
| [httpmethods](wiki/httpmethods.md) | HTTP method enumeration |
| [cors](wiki/cors.md) | CORS misconfiguration checker |
| [sqli](wiki/sqli.md) | SQL injection scanner |
| [xss](wiki/xss.md) | XSS vulnerability scanner |
| [admin](wiki/admin.md) | Admin panel finder |
| [openredirect](wiki/openredirect.md) | Open redirect checker |
| [lfi-rfi](wiki/lfi-rfi.md) | Local File Inclusion and Remote File Inclusion scanner |
| [cmd-injection](wiki/cmd-injection.md) | Command injection vulnerability scanner |
| [nosqli](wiki/nosqli.md) | NoSQL injection scanner (MongoDB, Redis, etc.) |
| [host-header-injection](wiki/host-header-injection.md) | Host header injection scanner |
| [crlf-injection](wiki/crlf-injection.md) | CRLF (HTTP Response Splitting) injection scanner |
| [proto-pollution](wiki/proto-pollution.md) | Server-side prototype pollution scanner (Node.js) |
| [deserialize](wiki/deserialize.md) | Insecure deserialization scanner (PHP, Python, Java, Ruby, .NET) |

### 4. Network & Infrastructure
Tools for network-level scanning, enumeration, and protocol analysis.

| Tool | Description |
|------|-------------|
| [net-scan](wiki/net-scan.md) | Network scanner (ARP discovery, ping sweep, OS fingerprinting, port scanning) |
| [snmp](wiki/snmp.md) | SNMP enumerator (community string brute force, MIB walk, interface/user extraction) |
| [smb](wiki/smb.md) | SMB enumerator (share listing, null session, OS version, RID cycle user enum) |
| [nfs](wiki/nfs.md) | NFS enumerator (export listing, mount checking, permission analysis, rpcbind query) |
| [ldap](wiki/ldap.md) | LDAP scanner (anonymous bind, attribute discovery, user/group dump, DN enumeration) |
| [rpc](wiki/rpc.md) | RPC enumerator (endpoint mapper dump, service discovery, unusual port detection) |

### 5. Auth & Credential Attacks
Authentication testing, password analysis, and credential discovery tools.

| Tool | Description |
|------|-------------|
| [cred-spray](wiki/cred-spray.md) | Credential sprayer (password spraying with anti-lockout detection and cooldown) |
| [default-creds](wiki/default-creds.md) | Default credential checker (500+ known device/service defaults) |
| [pass-analyze](wiki/pass-analyze.md) | Password strength analyzer (entropy, patterns, crack time estimation) |
| [hash-id](wiki/hash-id.md) | Hash identifier and cracker (50+ hash types, wordlist/rainbow table cracking) |

### 6. Cloud & Container Security
Cloud infrastructure, container, and Kubernetes security auditing tools.

| Tool | Description |
|------|-------------|
| [aws-enum](wiki/aws-enum.md) | AWS enumeration (IAM/S3/EC2/STS checks, bucket discovery, metadata probing) |
| [k8s](wiki/k8s.md) | Kubernetes security audit (RBAC, dashboard, etcd, kubelet, API server, pod/secret exposure) |
| [container](wiki/container.md) | Container security scanner (Docker API, breakout tests, image vulnerability check) |
| [cloud-meta](wiki/cloud-meta.md) | Cloud metadata exposure scanner (AWS, Azure, GCP, Alibaba, DigitalOcean, OpenStack) |

### 7. File & Metadata Analysis

| Tool | Description |
|------|-------------|
| [metadata](wiki/metadata.md) | File metadata/EXIF extraction |

### 8. Project Management & Reporting

| Tool | Description |
|------|-------------|
| [project](wiki/project.md) | Project database (SQLite-backed target/project management, scan comparison, run tracking) |
| [report](#report) | Pentest report generator (HTML/JSON/text from JSON output files) |

---

## Tool Reference

### admin
**Find admin panels and login pages.**  
Scans 250+ admin panel paths with CMS detection, fuzzy matching, login form analysis, and optional AI-assisted detection.

```
python3 main.py admin https://example.com
python3 main.py admin https://example.com --ollama-model llama3.2
```

### api-fuzz
**Advanced REST/GraphQL API fuzzer.**  
Tests header injection, parameter pollution, rate limiting, and endpoint discovery. Supports both REST and GraphQL APIs.

```
python3 main.py api-fuzz https://api.example.com --inject-headers --rate-limit
python3 main.py api-fuzz https://api.example.com/api/users --method POST --data '{"name":"test"}'
```

### asn
**ASN, network range, and ISP information lookup.**  
Uses ip-api.com, bgpview.io, and rdap.arin.net to resolve ASN details.

```
python3 main.py asn 8.8.8.8
python3 main.py asn AS15169
python3 main.py asn example.com
```

### auto-recon
**Autonomous reconnaissance orchestrator.**  
Chains 8-12 recon tools sequentially. Can optionally use AI to guide decisions and summarize findings.

```
python3 main.py auto-recon example.com
python3 main.py auto-recon example.com --ext --light
python3 main.py auto-recon example.com --use-ai --llm-provider openai
```

### aws-enum
**AWS enumeration.**  
Checks IAM, S3 buckets, EC2 metadata, and STS endpoints. Discovers open buckets and tests for metadata service exposure.

```
python3 main.py aws-enum --target example.com --s3 --metadata
python3 main.py aws-enum --bucket my-bucket-name
```

### breach
**Data breach checker.**  
Check emails against the HIBP API (k-anonymity model) and passwords against known breaches. Includes a built-in database of 40+ major breaches.

```
python3 main.py breach email@example.com
python3 main.py breach mypassword --type password
```

### brute
**Login brute forcer.**  
Attempts form-based, HTTP Basic, and Digest authentication brute force with automatic field detection.

```
python3 main.py brute --url http://example.com/login --user admin
python3 main.py brute --url http://example.com/wp-login.php --user-file users.txt --pass-file pass.txt
python3 main.py brute --url http://example.com/login --username admin --passwords password,123456,admin
```

### c2-hunt
**C2 infrastructure reconnaissance.**  
Hunts for command-and-control infrastructure using SSL fingerprints, blocklists, ThreatFox, and C2 panel path brute forcing.

```
python3 main.py c2-hunt example.com --check-paths
python3 main.py c2-hunt 185.130.5.173 --port 8080
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
Tests bucket names across 18+ cloud platforms including AWS S3, Azure Blob, GCP Storage, Firebase, Heroku, Netlify, Vercel, DigitalOcean Spaces, Alibaba OSS, Backblaze B2, Wasabi, Linode, Vultr, Scaleway, and more.

```
python3 main.py cloud example.com
```

### cloud-meta
**Cloud metadata exposure scanner.**  
Checks for exposed cloud metadata services across AWS, Azure, GCP, Alibaba, DigitalOcean, and OpenStack.

```
python3 main.py cloud-meta --check-all
python3 main.py cloud-meta --provider aws
```

### container
**Container security scanner.**  
Scans Docker API endpoints, tests for container breakout, checks image vulnerabilities, and audits container configurations.

```
python3 main.py container --target 192.168.1.100 --breakout
python3 main.py container --target 192.168.1.100 --images
```

### cors
**CORS misconfiguration checker.**  
Tests 10+ origin variations (null, subdomain, different domain, prefix, suffix, etc.) to find overly permissive CORS policies.

```
python3 main.py cors https://api.example.com
```

### crawl
**Recursive web crawler.**  
Crawls a website up to a specified depth, building a URL tree. Supports sitemap.xml and robots.txt discovery, concurrent fetching, and JS URL extraction.

```
python3 main.py crawl https://example.com --depth 3 --max-urls 200
```

### cred-spray
**Credential sprayer.**  
Password spraying tool with anti-lockout detection, configurable delay between attempts, and per-user password limits.

```
python3 main.py cred-spray https://example.com/login --username admin --passwords Password1,Welcome1
python3 main.py cred-spray https://example.com/login --user-file users.txt --pass-file pass.txt
```

### cve
**CVE vulnerability search.**  
Queries CIRCL, NVD, OpenCVE, and Omise CVE databases for known vulnerabilities matching a keyword.

```
python3 main.py cve log4j
python3 main.py cve wordpress --limit 50
```

### deep-search
**Cross-engine deep internet search.**  
Searches across 10 search engines for file types, code repositories, people, and generates dork queries.

```
python3 main.py deep-search "company name + credentials"
python3 main.py deep-search "domain.com" --limit 50
```

### default-creds
**Default credential checker.**  
Checks 500+ known default credentials against targets. Tests HTTP Basic Auth and reports known defaults by vendor/service/category.

```
python3 main.py default-creds https://example.com --category router
python3 main.py default-creds https://example.com --service tomcat
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

### email-finder
**Find email addresses from a domain.**  
Scrapes web pages, uses pattern guessing, LinkedIn name extraction, and search engine dorking to discover email addresses.

```
python3 main.py email-finder example.com
```

### email-recon
**Full email intelligence.**  
Performs breach checks (HIBP k-anonymity), social media presence lookup (20+ platforms), search engine footprint analysis, and Gravatar profile lookup.

```
python3 main.py email-recon john@example.com
```

### favicon
**Favicon hash calculator.**  
Downloads a site's favicon and computes its mmh3 hash for Shodan-based device identification.

```
python3 main.py favicon example.com
```

### forms
**HTML form security analysis.**  
Analyzes forms for password fields over HTTP, missing CSRF tokens, autocomplete, XSS in form fields, multipart detection, CORS preflight, and information disclosure.

```
python3 main.py forms https://example.com/login
python3 main.py forms https://example.com/login --ollama-model llama3.2
```

### fuzz
**URL fuzzing tool.**  
Tests URL parameters with fuzz payloads across 12+ vulnerability categories (XSS, SQLi, SSTI, path traversal, etc.).

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
python3 main.py github tensorflow/tensorflow --mode repo
python3 main.py github "api key" --mode search
```

### graphql
**GraphQL security scanner.**  
Discovers GraphQL endpoints, tests for introspection, batching attacks, query depth limits, alias bombing, and auth bypass.

```
python3 main.py graphql https://api.example.com/graphql
python3 main.py graphql https://api.example.com/graphql --auth-bypass
```

### hash-id
**Hash identifier and cracker.**  
Identifies 50+ hash types and attempts cracking with wordlists or rainbow tables.

```
python3 main.py hash-id --hash 5d41402abc4b2a76b9719d911017c592 --crack
python3 main.py hash-id --hash 5d41402abc4b2a76b9719d911017c592 --wordlist rockyou.txt
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

### jwt
**JWT analysis and attack toolkit.**  
Decodes JWT tokens, attempts secret cracking, tests algorithm confusion, KID injection, and JWK confusion.

```
python3 main.py jwt --token eyJhbGciOiJIUzI1NiIs...
python3 main.py jwt --token eyJ... --crack --wordlist rockyou.txt
python3 main.py jwt --token eyJ... --alg none
```

### k8s
**Kubernetes security audit.**  
Audits Kubernetes clusters for RBAC misconfigurations, dashboard exposure, etcd access, kubelet API, and pod/secret exposure.

```
python3 main.py k8s 192.168.1.100 --full
python3 main.py k8s https://k8s-api.example.com --insecure
```

### ldap
**LDAP scanner.**  
Tests anonymous bind, discovers attributes, and dumps users/groups from LDAP directories.

```
python3 main.py ldap 192.168.1.1 --dump
python3 main.py ldap 192.168.1.1 --base-dn dc=example,dc=com
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

### malware-hunt
**Multi-source malware URL & IOC hunter.**  
Searches URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, and URLScan for malware indicators.

```
python3 main.py malware-hunt example.com
python3 main.py malware-hunt 185.130.5.173 --type ip
python3 main.py malware-hunt 44d88612fea8a8f36de82e1278abb02f --type hash
```

### metadata
**Metadata extractor.**  
Extracts metadata/EXIF from images, PDFs, office documents, and audio files.

```
python3 main.py metadata /path/to/file.jpg
python3 main.py metadata /path/to/directory/
```

### net-scan
**Network scanner.**  
Performs ARP discovery, ping sweep, OS fingerprinting, and port scanning on local networks.

```
python3 main.py net-scan --subnet 192.168.1.0/24 --ping --os-detect
python3 main.py net-scan --target 192.168.1.1 --ports 22,80,443
```

### nfs
**NFS enumerator.**  
Lists exported NFS shares, checks mount permissions, and queries rpcbind for service information.

```
python3 main.py nfs 192.168.1.1
```

### openredirect
**Open redirect checker.**  
Tests URL parameters for open redirect vulnerabilities using 12 payload types, validation bypass, JS/DOM discovery, CRLF injection, and parameter pollution.

```
python3 main.py openredirect https://example.com/page?url=http://evil.com
python3 main.py openredirect https://example.com
```

### pass-analyze
**Password strength analyzer.**  
Analyzes password entropy, common patterns, and estimates crack time.

```
python3 main.py pass-analyze --password MyP@ssw0rd!
python3 main.py pass-analyze --passwords pass1,pass2,pass3 --verbose
```

### pastewatch
**Pastebin monitoring and leak detection.**  
Searches paste sites (Pastebin, PSBDMP, Paste.ee, Hastebin, Ghostbin, Rentry, and more) for emails, domains, or keywords and monitors for new leaks.

```
python3 main.py pastewatch email@example.com
python3 main.py pastewatch "company name + credentials"
```

### phish-hunt
**Phishing infrastructure hunter.**  
Hunts for phishing infrastructure using URLScan phishing search, certificate monitoring, phishing kit discovery, and Google dorking.

```
python3 main.py phish-hunt example.com --deep
python3 main.py phish-hunt "paypal" --deep
```

### phone-info
**Phone number intelligence.**  
Looks up country, carrier, line type, location, and reputation for a phone number.

```
python3 main.py phone-info "+14155551234"
```

### phone-social
**Social media finder for phone numbers.**  
Finds social media and messaging accounts linked to a phone number.

```
python3 main.py phone-social "+14155551234"
```

### port-scan
**TCP port scanner.**  
Scans common ports with banner grabbing and multi-threading.

```
python3 main.py port-scan example.com
python3 main.py port-scan 192.168.1.1 --ports 1-1000
python3 main.py port-scan example.com --ports 22,80,443,3306
```

### project
**Project database management.**  
SQLite-backed project management system for organizing targets, saving scan results, comparing runs, and tracking engagement history.

```
python3 main.py project --cmd init --name engagement1 --target example.com
python3 main.py project --cmd save --project engagement1 --tool port-scan --file results.json
python3 main.py project --cmd compare --compare 1,2
```

### race
**Race condition tester.**  
Tests for race conditions by sending concurrent requests. Supports coupon/discount, OTP bypass, and rate-limit bypass scenarios.

```
python3 main.py race https://example.com/coupon --threads 50
python3 main.py race https://example.com/apply --param coupon=TEST --scenario coupon
```

### redirects
**Redirect chain tracker.**  
Traces the full HTTP redirect chain with security analysis, detecting loops, HTTPS to HTTP downgrades, and open redirects.

```
python3 main.py redirects example.com
python3 main.py redirects example.com --ollama-model llama3.2
```

### reddit-osint
**Reddit OSINT.**  
Analyzes Reddit user profiles, subreddits, and performs keyword searches across Reddit.

```
python3 main.py reddit-osint some_user
python3 main.py reddit-osint programming --mode subreddit
python3 main.py reddit-osint "keyword" --mode search
```

### report
**Pentest report generator.**  
Consumes JSON output files from any tool and generates professional HTML, JSON, or text reports.

```
python3 main.py report --input results.json --format html
python3 main.py report --input scan1.json,scan2.json --output report.html --title "Pentest Report"
python3 main.py report --input all_results.json --format json
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

### rpc
**RPC enumerator.**  
Dumps RPC endpoint mapper, discovers RPC services, and detects unusual port mappings.

```
python3 main.py rpc 192.168.1.1
```

### shodan
**Shodan.io search.**  
Searches Shodan for devices, services, and open ports. Supports host lookup and search query modes.

```
python3 main.py shodan example.com
python3 main.py shodan --query "apache 2.4.49 country:US"
python3 main.py shodan example.com --ollama-model llama3.2
```

### smb
**SMB enumerator.**  
Lists SMB shares, tests null sessions, enumerates users via RID cycling, and detects OS version.

```
python3 main.py smb 192.168.1.1 --dump
python3 main.py smb 192.168.1.1 --null-session
```

### smuggle
**HTTP request smuggler.**  
Detects and exploits HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).

```
python3 main.py smuggle example.com --port 80
python3 main.py smuggle example.com --port 443 --tls
```

### smtp
**SMTP enumeration.**  
Resolves MX records, connects to SMTP servers, enumerates supported commands, and checks for open relay.

```
python3 main.py smtp example.com
python3 main.py smtp example.com --port 587
```

### snmp
**SNMP enumerator.**  
Brute-forces SNMP community strings, walks MIB trees, and extracts interfaces, users, and processes.

```
python3 main.py snmp 192.168.1.1 --walk
python3 main.py snmp 192.168.1.1 --community public
```

### social-recon
**Cross-platform social media recon.**  
Searches 60+ social platforms for a username, extracts profile metadata, and correlates findings.

```
python3 main.py social-recon username --threads 150
```

### sociallinks
**Social media link extractor.**  
Finds links to 40+ social media platforms in a website's HTML, validates them with HEAD requests, and extracts OG/title metadata.

```
python3 main.py sociallinks https://example.com
```

### sqli
**SQL injection scanner.**  
Tests URL parameters with 200+ SQL injection payloads and checks responses for error patterns, time-based detection, and WAF bypass.

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

### ssrf
**SSRF vulnerability scanner.**  
Detects blind and reflected Server-Side Request Forgery with out-of-band verification and cloud metadata probing.

```
python3 main.py ssrf --url "http://example.com/page?url=SSRF"
python3 main.py ssrf --url "http://example.com/page?url=SSRF" --blind
python3 main.py ssrf --urls "http://site1.com?q=SSRF,http://site2.com?url=SSRF"
```

### ssti
**SSTI scanner.**  
Scans for Server-Side Template Injection across 9 template engines (Jinja2, Twig, Freemarker, Velocity, Jade, ERB, Tornado, Mako, Smarty).

```
python3 main.py ssti https://example.com/page?name=test
python3 main.py ssti https://example.com/page?name=test --rce
```

### subdomain
**Subdomain finder.**  
Brute-forces subdomains using a built-in list of 1000+ common subdomains. Supports external tools (sublist3r, amass, assetfinder).

```
python3 main.py subdomain example.com
python3 main.py subdomain example.com -w /path/to/wordlist.txt
```

### takeover
**Subdomain takeover detector.**  
Checks CNAME records against 20+ cloud services (AWS, Azure, GitHub, Heroku, Netlify, etc.) for unclaimed resources.

```
python3 main.py takeover --domain sub.example.com
python3 main.py takeover --domains sub1.example.com,sub2.example.com
```

### tech
**Technology detector.**  
Identifies 100+ web technologies including CMS, frameworks, CDN, WAF, analytics, JS libraries, and databases.

```
python3 main.py tech example.com
```

### telegram-osint
**Telegram OSINT.**  
Analyzes Telegram channels and groups, extracts message patterns, tracks forwards, and identifies activity patterns.

```
python3 main.py telegram-osint @channel_name --deep
python3 main.py telegram-osint username --limit 50
```

### tor-check
**Tor/dark web reconnaissance.**  
Checks for .onion mirrors, exit node presence, and performs dark web searches.

```
python3 main.py tor-check example.com
```

### username
**Username search.**  
Searches for a username across 100+ social media and web platforms (sherlock-style). Supports automatic case variants with `--variants`.

```
python3 main.py username john
python3 main.py username john --platforms github,twitter,reddit
python3 main.py username JohnDoe --variants
```

### waf
**WAF detector.**  
Detects 30+ Web Application Firewalls and reverse proxies by analyzing response headers/cookies and probing with malicious payloads.

```
python3 main.py waf https://example.com
```

### wayback
**Wayback Machine scraper.**  
Fetches historical snapshots of a domain from the Wayback Machine CDX API.

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

### ws
**WebSocket security tester.**  
Tests WebSocket connections for origin bypass, message fuzzing, and DoS resistance.

```
python3 main.py ws wss://example.com/ws --fuzz --dos
python3 main.py ws wss://example.com/ws --origin https://attacker.com
```

### xss
**XSS scanner.**  
Tests URL parameters and forms with 150+ XSS payloads including context-aware, polyglot, DOM, stored, mXSS, and CSP analysis.

```
python3 main.py xss https://example.com/page?q=test
```

### xxe
**XXE scanner.**  
Scans for XML External Entity injection with file read, SSRF, and blind exfiltration across 9 DOCTYPE variants including XInclude and SVG.

```
python3 main.py xxe https://example.com/xml --file-read /etc/passwd
python3 main.py xxe https://example.com/upload --collaborator your.oob.provider
```

### lfi-rfi
**Local File Inclusion and Remote File Inclusion scanner.**  
Tests 50+ path traversal payloads including PHP wrappers, RFI inclusion, null byte injection, /proc/self/environ, and log poisoning. Detects file reads, PHP filter leaks, and remote code execution via data:// and expect:// wrappers.

```
python3 main.py lfi-rfi https://example.com/page?file=test
python3 main.py lfi-rfi https://example.com --params file,page,path --ollama-model llama3.2
python3 main.py lfi-rfi https://example.com/page --method POST --data "file=test"
```

### cmd-injection
**Command injection vulnerability scanner.**  
Tests 40+ command injection payloads including semicolon, pipe, subshell, backtick, and newline injection. Uses time-based detection (sleep/ping delays) and output-based verification for blind and reflected command execution.

```
python3 main.py cmd-injection https://example.com/ping?host=test
python3 main.py cmd-injection https://example.com --params ip,host,domain --ollama-model llama3.2
python3 main.py cmd-injection https://example.com/traceroute --method POST --data "target=test"
```

### nosqli
**NoSQL injection scanner.**  
Tests for MongoDB and NoSQL injection vulnerabilities using $ne, $gt, $regex, $where operators in both query strings and JSON body injection. Detects authentication bypass and data manipulation in NoSQL-backed applications.

```
python3 main.py nosqli https://example.com/login?username=admin
python3 main.py nosqli https://example.com/api/login --method POST --data '{"username":"admin","password":"test"}'
python3 main.py nosqli https://example.com/search?q=test --ollama-model llama3.2
```

### email-security
**Email security analyzer.**  
Checks SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting & Conformance) DNS records. Computes an email security score (A-F grade) and identifies spoofing vulnerabilities.

```
python3 main.py email-security example.com
python3 main.py email-security example.com --selector google
```

### host-header-injection
**Host header injection scanner.**  
Sends 15+ Host header tamper variants plus X-Forwarded-Host, X-Original-URL, and Forwarded header injections. Tests for cache poisoning, password reset poisoning, SSRF via host, and virtual host routing bypass.

```
python3 main.py host-header-injection https://example.com
python3 main.py host-header-injection https://example.com --ollama-model llama3.2
```

### crlf-injection
**CRLF (HTTP Response Splitting) injection scanner.**  
Injects %0d%0a, %0a, %0d sequences in URL parameters and headers to test for HTTP response splitting. Detects Set-Cookie injection, Location header injection, cache poisoning, and XSS via CRLF.

```
python3 main.py crlf-injection https://example.com/page?file=test
python3 main.py crlf-injection https://example.com --params file,url,next --ollama-model llama3.2
```

### proto-pollution
**Server-side prototype pollution scanner.**  
Tests Node.js applications for prototype pollution via __proto__ and constructor.prototype in JSON bodies, query strings, and custom headers. Detects admin bypass, property injection, and potential RCE vectors.

```
python3 main.py proto-pollution https://example.com/api/user
python3 main.py proto-pollution https://example.com --method POST --ollama-model llama3.2
```

### deserialize
**Insecure deserialization scanner.**  
Tests PHP serialized objects (O:), Python pickle (cos), Java serialized streams (aced0005), Ruby YAML, and .NET PowerShell objects. Sends payloads across multiple Content-Type variants and detects deserialization errors and RCE indicators.

```
python3 main.py deserialize https://example.com/api/upload
python3 main.py deserialize https://example.com --param data --ollama-model llama3.2
```

### screenshot
**Website screenshot tool.**  
Captures full-page screenshots using Playwright (headless Chromium). Configurable viewport size, full-page capture, and custom output directory. Falls back to HTTP status check if Playwright is not installed.

```
python3 main.py screenshot https://example.com
python3 main.py screenshot https://example.com --output-dir reports --full-page
python3 main.py screenshot https://example.com --width 1920 --height 1080
```

### wordlist
**Custom wordlist generator.**  
Scrapes target websites to extract words, URLs, paths, form fields, CSS classes, and JS endpoints. Applies leetspeak mutations and case variants. Optionally uses AI for target-specific word suggestions. Supports small/medium/large output sizes with configurable min/max length.

```
python3 main.py wordlist https://example.com --size large --mutation
python3 main.py wordlist https://example.com --out custom.txt --depth 3
python3 main.py wordlist https://example.com --min-len 4 --max-len 20 --ollama-model llama3.2
```

### ai-chat
**Autonomous AI assistant that runs security tools via natural language.**  
Interactive chat interface supporting OpenAI, Anthropic, Gemini, and Ollama providers. Can autonomously execute any of the 92 tools in the suite, chain multiple tools together, and summarize findings using natural language conversations.

```
python3 main.py ai-chat
python3 main.py ai-chat --provider openai --model gpt-4o-mini
python3 main.py ai-chat --provider anthropic --model claude-3-5-sonnet-20241022
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
