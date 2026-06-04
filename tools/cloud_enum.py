import requests
import json
from urllib.parse import urlparse
from utils.output import section, info, success, warning, error, result

CLOUD_SERVICES = {
    "AWS S3": {
        "domains": ["{name}.s3.amazonaws.com", "{name}.s3.amazonaws.com", "{name}.s3.us-east-1.amazonaws.com",
                     "{name}.s3-website-us-east-1.amazonaws.com", "{name}.s3-website-ap-southeast-1.amazonaws.com"],
        "check": lambda r: r.status_code not in (404,) and "NoSuchBucket" not in r.text,
    },
    "AWS CloudFront": {
        "domains": ["{name}.cloudfront.net"],
        "check": lambda r: r.status_code not in (404, 403) and "CloudFront" in r.headers.get("Server", ""),
    },
    "Azure Blob": {
        "domains": ["{name}.blob.core.windows.net", "{name}.blob.core.windows.net/$root"],
        "check": lambda r: r.status_code not in (404,) and "ResourceNotFound" not in r.text,
    },
    "Azure App Service": {
        "domains": ["{name}.azurewebsites.net"],
        "check": lambda r: r.status_code not in (404,) and "Azure App Service" in r.text,
    },
    "Google Cloud Storage": {
        "domains": ["{name}.storage.googleapis.com", "{name}.appspot.com"],
        "check": lambda r: r.status_code not in (404,) and "NoSuchBucket" not in r.text,
    },
    "DigitalOcean Spaces": {
        "domains": ["{name}.{region}.digitaloceanspaces.com"],
        "check": lambda r: r.status_code not in (404,) and "NoSuchBucket" not in r.text,
    },
    "Firebase": {
        "domains": ["{name}.firebaseio.com", "{name}.firebaseio.com/.json"],
        "check": lambda r: r.status_code == 200,
    },
    "Heroku": {
        "domains": ["{name}.herokuapp.com"],
        "check": lambda r: r.status_code not in (404,) and "There's nothing here" not in r.text,
    },
    "GitHub Pages": {
        "domains": ["{name}.github.io"],
        "check": lambda r: r.status_code not in (404,) and "404" not in r.text[:500],
    },
    "Netlify": {
        "domains": ["{name}.netlify.app"],
        "check": lambda r: r.status_code not in (404,) and "Not Found" not in r.text[:500],
    },
    "Vercel": {
        "domains": ["{name}.vercel.app"],
        "check": lambda r: r.status_code not in (404,) and "Not Found" not in r.text[:500],
    },
    "Surge": {
        "domains": ["{name}.surge.sh"],
        "check": lambda r: r.status_code not in (404,),
    },
    "Bitbucket": {
        "domains": ["{name}.bitbucket.io"],
        "check": lambda r: r.status_code not in (404,),
    },
    "Render": {
        "domains": ["{name}.onrender.com"],
        "check": lambda r: r.status_code not in (404,),
    },
    "Fly.io": {
        "domains": ["{name}.fly.dev"],
        "check": lambda r: r.status_code not in (404,),
    },
    "Railway": {
        "domains": ["{name}.railway.app"],
        "check": lambda r: r.status_code not in (404,),
    },
}


class CloudEnum:
    name = "cloud"
    description = "Enumerate cloud storage and hosting services"

    @staticmethod
    def run(target, timeout=10):
        section(f"Cloud Service Enumeration: {target}")

        domain = target.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split("://")[-1].split("/")[0].split(":")[0]

        bucket_name = domain.split(".")[0]
        domain_name = domain.replace(".", "-")

        names_to_test = [bucket_name, domain_name]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
                   "ap-southeast-1", "ap-northeast-1", "sa-east-1"]

        info(f"Testing bucket/hosting names derived from {domain}...")
        info(f"Names to test: {names_to_test}")

        found = []

        for name in names_to_test:
            for service_name, service_info in CLOUD_SERVICES.items():
                for domain_template in service_info["domains"]:
                    test_url = f"https://{domain_template.format(name=name, region='us-east-1')}"
                    if "{region}" in domain_template:
                        for region in regions:
                            test_url = f"https://{domain_template.format(name=name, region=region)}"
                            test_url_no_region = f"https://{domain_template.format(name=name, region='us-east-1')}"
                            if test_url != test_url_no_region:
                                CloudEnum.test_endpoint(test_url, service_name, timeout, found)
                    else:
                        CloudEnum.test_endpoint(test_url, service_name, timeout, found)

        section("Cloud Enumeration Results")
        if found:
            success(f"Found {len(found)} accessible cloud resources:")
            for f in found:
                result(f"  [{f['service']}]", f"{f['url']} (HTTP {f['status']})")
        else:
            info("No accessible cloud resources found")

        return {"target": domain, "found": found}

    @staticmethod
    def test_endpoint(url, service_name, timeout, found_list):
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            check_fn = CLOUD_SERVICES[service_name]["check"]
            if check_fn(resp):
                success(f"[{service_name}] {url} (HTTP {resp.status_code})")
                found_list.append({"service": service_name, "url": url, "status": resp.status_code})
            else:
                info(f"[{service_name}] {url} -> {resp.status_code} (not accessible)")
        except Exception:
            pass
