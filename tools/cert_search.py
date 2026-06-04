import requests
from utils.output import section, info, success, warning, error, result, table

CRTSH_URL = "https://crt.sh/?q={}&output=json"
CERTSPOTTER_URL = "https://certspotter.com/api/v0/certs?domain={}"


def search_crtsh(domain):
    try:
        resp = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            return data
        return None
    except Exception as e:
        error(f"crt.sh error: {e}")
        return None


def search_certspotter(domain):
    try:
        resp = requests.get(
            f"https://certspotter.com/api/v0/certs?domain={domain}",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            names = set()
            for entry in data:
                for name in entry.get("dns_names", []):
                    names.add(name.strip().lower())
            return list(names)
        return None
    except:
        return None


class CertSearch:
    name = "certsearch"
    description = "Search Certificate Transparency logs for domain subdomains and certificates"

    @staticmethod
    def run(target, all=False):
        section(f"Certificate Transparency Search: {target}")

        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target

        all_names = set()
        source = ""

        info("Querying crt.sh...")
        data = search_crtsh(target)
        if data:
            source = "crt.sh"
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and target in n:
                            all_names.add(n)

            success(f"Found {len(all_names)} certificate entries from crt.sh")
        else:
            warning("crt.sh query failed or returned no results")

        info("Querying CertSpotter...")
        cs_names = search_certspotter(target)
        if cs_names:
            source = "CertSpotter (fallback)" if not source else "crt.sh + CertSpotter"
            for n in cs_names:
                if target in n:
                    all_names.add(n)
            info(f"CertSpotter returned {len(cs_names)} names")

        if not all_names:
            error("No certificate data found from any source")
            return {"target": target, "error": "No results"}

        domains_only = set()
        subdomains = set()
        wildcards = set()

        for name in all_names:
            name = name.strip().lower()
            if name.startswith("*."):
                wildcards.add(name[2:])
                domains_only.add(name[2:])
            elif name == target:
                domains_only.add(name)
            elif name.endswith("." + target):
                subdomains.add(name)
                domains_only.add(name)
            else:
                domains_only.add(name)

        section("Summary")
        result("Source", source)
        result("Total entries", str(len(all_names)))
        result("Unique domains", str(len(domains_only)))
        result("Subdomains", str(len(subdomains)))
        result("Wildcards", str(len(wildcards)))

        if wildcards:
            section("Wildcard Certificates")
            for w in sorted(wildcards):
                result("  *." + target, w)

        if subdomains:
            section(f"Subdomains ({len(subdomains)})")
            sorted_subdomains = sorted(subdomains)
            for sd in sorted_subdomains[:100]:
                success(sd)

            section("Subdomains by Level")
            level_count = {}
            for sd in sorted_subdomains:
                level = sd.count(".")
                level_count[level] = level_count.get(level, 0) + 1
            for level in sorted(level_count):
                result(f"  Level {level}", f"{level_count[level]} subdomains")

            if len(sorted_subdomains) > 100:
                info(f"... and {len(sorted_subdomains) - 100} more subdomains")

        found_subdomains = sorted(subdomains)
        return {"target": target, "subdomains": found_subdomains, "total": len(all_names)}
