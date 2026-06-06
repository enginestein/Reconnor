import requests
from utils.output import section, info, success, warning, error, result, table


API_URLS = [
    "https://cve.circl.lu/api/cvefor/{query}",
    "https://cve.circl.lu/api/search/{query}",
    "https://cve.omise.co/api/cve/{query}",
    "https://www.opencve.io/api/cve?search={query}",
]

TIMEOUT = 20


def check_circl_alive():
    try:
        resp = requests.get(
            "https://cve.circl.lu/api/last",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        return resp.status_code == 200
    except:
        return False


def search_cve_circl(query, limit=20):
    url = f"https://cve.circl.lu/api/cvefor/{query}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data[:limit]
        return None
    except:
        return None


def search_cve_omise(query, limit=20):
    url = f"https://cve.omise.co/api/cve/{query}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data[:limit]
        return None
    except:
        return None


def search_cve_opencve(query, limit=20):
    url = f"https://www.opencve.io/api/cve?search={query}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data[:limit]
        return None
    except:
        return None


def search_nvd(query, limit=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": min(limit, 20),
    }
    try:
        resp = requests.get(url, params=params, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            return vulns[:limit]
        return None
    except:
        return None


class CVESearch:
    name = "cve"
    description = "Search for known vulnerabilities (CVEs)"

    @staticmethod
    def run(target, limit=20):
        section(f"CVE Search: {target}")

        results = []
        source = None

        info(f"Searching for CVEs related to '{target}'...")

        if not check_circl_alive():
            warning("CIRCL API health check failed, trying fallback sources...")
        else:
            data = search_cve_circl(target, limit)
            if data:
                source = "cve.circl.lu"
                for item in data:
                    cve_id = item.get("id", "N/A")
                    summary = item.get("summary", "No description")
                    cvss = item.get("cvss", "N/A")
                    results.append((cve_id, cvss, summary[:200]))

        if not results:
            warning("No results from CIRCL, trying omise.co...")
            data = search_cve_omise(target, limit)
            if data:
                source = "cve.omise.co"
                for item in data:
                    cve_id = item.get("id", "N/A")
                    summary = item.get("summary", "No description")
                    cvss = item.get("cvss", "N/A")
                    results.append((cve_id, cvss, summary[:200]))

        if not results:
            warning("No results from omise.co, trying opencve.io...")
            data = search_cve_opencve(target, limit)
            if data:
                source = "opencve.io"
                for item in data:
                    cve_id = item.get("id", "N/A")
                    summary = item.get("summary", "No description")
                    cvss = item.get("cvss", "N/A")
                    results.append((cve_id, cvss, summary[:200]))

        if not results:
            warning("No results from opencve.io, trying NVD...")
            data = search_nvd(target, limit)
            if data:
                source = "NVD"
                for item in data:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    descriptions = cve.get("descriptions", [{"value": "No description"}])
                    summary = descriptions[0].get("value", "No description")
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A") if metrics.get("cvssMetricV31") else "N/A"
                    results.append((cve_id, cvss_v3, summary[:200]))

        if results:
            info(f"Source: {source}")
            success(f"Found {len(results)} CVE(s):")
            table(
                ["CVE ID", "CVSS", "DESCRIPTION"],
                results
            )
        else:
            warning("No CVEs found for this search term")

        return {"target": target, "results": results, "source": source}
