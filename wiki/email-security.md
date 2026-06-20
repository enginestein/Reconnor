# Email Security Analyzer

Email security analyzer that checks SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting & Conformance) DNS records. Computes an email security score and identifies spoofing vulnerabilities.

```
python3 main.py email-security example.com
python3 main.py email-security example.com --selector google
```

**Options:**
- `--selector` -- DKIM selector name to query (default: "default"; auto-tries common selectors if not found)
- `--timeout` -- DNS query timeout in seconds (default: 10)

**How it works:** Resolves MX records, SPF TXT records (v=spf1), DKIM TXT records (selector._domainkey), and DMARC TXT records (_dmarc). Analyzes SPF mechanisms (pass-all, fail-all, includes), DKIM key presence, and DMARC policies (none/quarantine/reject). Computes a weighted email security score from 0-100 with letter grade.
