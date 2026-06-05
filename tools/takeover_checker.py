import json
import socket
import dns.resolver
import concurrent.futures
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result, table


class TakeoverChecker:
    description = "Subdomain takeover vulnerability detection (AWS, Azure, GitHub, Heroku, etc.)"

    FINGERPRINTS = {
        "aws-s3": {
            "domains": ["s3.amazonaws.com", "s3-website", "s3.us-east-2.amazonaws.com"],
            "fingerprints": ["NoSuchBucket", "The specified bucket does not exist", "404 Not Found"],
            "service": "AWS S3",
        },
        "azure": {
            "domains": ["azurewebsites.net", "azure-mobile.net", "cloudapp.net", "trafficmanager.net", "azure-api.net", "azureedge.net", "azurefd.net"],
            "fingerprints": ["The specified resource was not found", "404 Not Found", "There is no site deployed"],
            "service": "Azure",
        },
        "github-pages": {
            "domains": ["github.io"],
            "fingerprints": ["There isn't a GitHub Pages site here", "404 Not Found"],
            "service": "GitHub Pages",
        },
        "heroku": {
            "domains": ["herokuapp.com", "herokussl.com"],
            "fingerprints": ["No such app", "There is no app", "Heroku | No such app"],
            "service": "Heroku",
        },
        "fastly": {
            "domains": ["fastly.net", "global.ssl.fastly.net"],
            "fingerprints": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
            "service": "Fastly",
        },
        "shopify": {
            "domains": ["myshopify.com", "shopify.com"],
            "fingerprints": ["Sorry, this shop is currently unavailable"],
            "service": "Shopify",
        },
        "wordpress": {
            "domains": ["wordpress.com"],
            "fingerprints": ["Do you want to register", "No site for domain"],
            "service": "WordPress.com",
        },
        "readme": {
            "domains": ["readme.io"],
            "fingerprints": ["Project doesnt exist", "Page Not Found"],
            "service": "ReadMe.io",
        },
        "cloudflare": {
            "domains": ["cloudflare.com"],
            "fingerprints": ["This domain is not configured on Cloudflare"],
            "service": "Cloudflare",
        },
        "surge": {
            "domains": ["surge.sh"],
            "fingerprints": ["project not found"],
            "service": "Surge",
        },
        "pantheon": {
            "domains": ["pantheonsite.io"],
            "fingerprints": ["The gods are angry", "The requested page could not be found"],
            "service": "Pantheon",
        },
        "bitbucket": {
            "domains": ["bitbucket.io"],
            "fingerprints": ["The page you were looking for doesn't exist", "Repository not found"],
            "service": "Bitbucket",
        },
        "gitlab": {
            "domains": ["gitlab.io"],
            "fingerprints": ["The page you're looking for could not be found"],
            "service": "GitLab Pages",
        },
        "fly": {
            "domains": ["fly.dev"],
            "fingerprints": ["404 Not Found", "App Not Found"],
            "service": "Fly.io",
        },
        "netlify": {
            "domains": ["netlify.app"],
            "fingerprints": ["Not Found - Request ID:", "Page Not Found"],
            "service": "Netlify",
        },
        "unbounce": {
            "domains": ["unbouncepages.com"],
            "fingerprints": ["The page you were looking for doesn't exist"],
            "service": "Unbounce",
        },
        "strikingly": {
            "domains": ["strikingly.com", "strikinglydns.com"],
            "fingerprints": ["The page cannot be found", "Page not found"],
            "service": "Strikingly",
        },
        "zendesk": {
            "domains": ["zendesk.com"],
            "fingerprints": ["Help Center Closed", "This help center is no longer available"],
            "service": "Zendesk",
        },
        "freshdesk": {
            "domains": ["freshdesk.com"],
            "fingerprints": ["The page you were looking for doesn't exist"],
            "service": "Freshdesk",
        },
        "aha": {
            "domains": ["aha.io"],
            "fingerprints": ["There is no Aha! site at this address"],
            "service": "Aha!",
        },
        "campaignmonitor": {
            "domains": ["createsend.com", "campaignmonitor.com"],
            "fingerprints": ["Trying to access your account"],
            "service": "Campaign Monitor",
        },
    }

    @staticmethod
    def run(domain="", domains="", threads=20, timeout=10, **kwargs):
        section("Subdomain Takeover Checker")

        targets = []
        if domain:
            targets.append(domain)
        if domains:
            targets.extend(d.strip() for d in domains.split(",") if d.strip())

        if not targets:
            if kwargs.get("target"):
                targets.append(kwargs["target"])
            else:
                error("No domain provided (use --domain or --domains)")
                return {"error": "no targets"}

        result_data = {"targets": targets, "vulnerable": [], "cname_records": []}

        for target in targets:
            section(f"Checking: {target}")
            info(f"Resolving CNAME records for {target}")

            try:
                answers = dns.resolver.resolve(target, "CNAME", lifetime=timeout)
                for rdata in answers:
                    cname = str(rdata).rstrip(".")
                    cname_lower = cname.lower()
                    result("CNAME", cname)
                    result_data["cname_records"].append({"domain": target, "cname": cname})

                    for service_name, fp in TakeoverChecker.FINGERPRINTS.items():
                        for fp_domain in fp["domains"]:
                            if fp_domain in cname_lower:
                                info(f"CNAME points to {fp['service']} - checking for takeover")
                                if TakeoverChecker._check_takeover(cname, target, fp, timeout):
                                    vulnerable = {
                                        "domain": target,
                                        "cname": cname,
                                        "service": fp["service"],
                                        "fingerprint": fp["fingerprints"][0],
                                    }
                                    result_data["vulnerable"].append(vulnerable)
                                    warning(f"POTENTIAL TAKEOVER: {target} -> {cname} ({fp['service']})")
                                break
            except dns.resolver.NoAnswer:
                info(f"No CNAME record for {target}")
            except dns.resolver.NXDOMAIN:
                info(f"NXDOMAIN for {target}")
            except dns.resolver.LifetimeTimeout:
                warning(f"DNS timeout for {target}")
            except:
                info(f"Could not resolve {target}")

        section("Takeover Check Complete")
        if result_data["vulnerable"]:
            warning(f"Found {len(result_data['vulnerable'])} potential takeover vulnerabilities!")
            rows = [[v["domain"], v["cname"], v["service"]] for v in result_data["vulnerable"]]
            table(["Domain", "CNAME Target", "Service"], rows)
        else:
            success("No takeover vulnerabilities detected")

        return result_data

    @staticmethod
    def _check_takeover(cname, domain, fingerprint, timeout):
        import urllib.request
        try:
            req = urllib.request.Request(f"http://{domain}", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                for fp in fingerprint["fingerprints"]:
                    if fp.lower() in body.lower():
                        return True
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            for fp in fingerprint["fingerprints"]:
                if fp.lower() in body.lower():
                    return True
        except:
            pass
        return False
