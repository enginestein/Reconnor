import json
import urllib.request
import socket
import re
from utils.output import section, info, success, warning, error, result, table


class CloudMetadata:
    description = "Advanced cloud metadata exposure scanner: AWS, Azure, GCP, Alibaba, DigitalOcean, OpenStack"

    ENDPOINTS = {
        "AWS": {
            "base": "http://169.254.169.254",
            "paths": [
                "/latest/meta-data/",
                "/latest/meta-data/iam/security-credentials/",
                "/latest/meta-data/iam/info",
                "/latest/user-data/",
                "/latest/meta-data/public-keys/",
                "/latest/meta-data/network/interfaces/macs/",
                "/latest/dynamic/instance-identity/document",
                "/latest/meta-data/hostname",
                "/latest/meta-data/local-ipv4",
                "/latest/meta-data/public-ipv4",
                "/latest/meta-data/instance-id",
                "/latest/meta-data/ami-id",
            ],
            "headers": {},
        },
        "GCP": {
            "base": "http://metadata.google.internal",
            "paths": [
                "/computeMetadata/v1/",
                "/computeMetadata/v1/instance/service-accounts/",
                "/computeMetadata/v1/instance/service-accounts/default/token",
                "/computeMetadata/v1/instance/",
                "/computeMetadata/v1/project/",
                "/computeMetadata/v1/instance/attributes/",
                "/computeMetadata/v1/instance/network-interfaces/",
                "/computeMetadata/v1/instance/disks/",
            ],
            "headers": {"Metadata-Flavor": "Google"},
        },
        "Azure": {
            "base": "http://169.254.169.254",
            "paths": [
                "/metadata/instance?api-version=2021-02-01",
                "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com",
                "/metadata/instance/compute?api-version=2021-02-01",
                "/metadata/instance/network?api-version=2021-02-01",
            ],
            "headers": {"Metadata": "true"},
        },
        "Alibaba": {
            "base": "http://100.100.100.200",
            "paths": [
                "/latest/meta-data/",
                "/latest/meta-data/instance-id",
                "/latest/meta-data/region-id",
                "/latest/meta-data/image-id",
                "/latest/meta-data/network-type",
                "/latest/meta-data/private-ipv4",
                "/latest/meta-data/public-ipv4",
                "/latest/meta-data/ram/security-credentials/",
                "/latest/user-data/",
            ],
            "headers": {},
        },
        "DigitalOcean": {
            "base": "http://169.254.169.254",
            "paths": [
                "/metadata/v1.json",
                "/metadata/v1/id",
                "/metadata/v1/hostname",
                "/metadata/v1/user-data",
                "/metadata/v1/region",
                "/metadata/v1/interfaces/public/0/anchor_ipv4/address",
                "/metadata/v1/interfaces/private/0/ipv4/address",
                "/metadata/v1/droplet_id",
            ],
            "headers": {},
        },
        "OpenStack": {
            "base": "http://169.254.169.254",
            "paths": [
                "/openstack",
                "/openstack/latest/meta_data.json",
                "/openstack/latest/network_data.json",
                "/openstack/latest/user_data",
                "/openstack/latest/password",
                "/openstack/latest/vendor_data.json",
            ],
            "headers": {},
        },
    }

    @staticmethod
    def run(target="", provider="", timeout=5, check_all=True, **kwargs):
        section("Cloud Metadata Exposure Scanner")

        result_data = {
            "providers_accessible": [],
            "findings": {},
        }

        providers_to_check = [provider] if provider else CloudMetadata.ENDPOINTS.keys()

        for prov in providers_to_check:
            if prov not in CloudMetadata.ENDPOINTS:
                continue

            ep = CloudMetadata.ENDPOINTS[prov]
            section(f"{prov} Metadata")

            accessible = False
            provider_findings = {}

            for path in ep["paths"]:
                url = f"{ep['base']}{path}"
                try:
                    req = urllib.request.Request(url, headers=ep["headers"])
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace").strip()[:500]
                        if body:
                            accessible = True
                            provider_findings[url] = body
                            if "iam" in path.lower() or "security" in path.lower() or "token" in path.lower() or "key" in path.lower() or "password" in path.lower():
                                warning(f"CREDENTIAL EXPOSURE: {url}")
                                success(f"Data: {body[:200]}")
                            elif body and len(body) > 10:
                                result(path.split("/")[-1], body[:100])
                            else:
                                info(f"Accessible: {path.split('/')[-1]}")
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        pass
                    elif e.code in (403, 401):
                        info(f"Protected ({e.code}): {path.split('/')[-1]}")
                except:
                    pass

            if accessible:
                result_data["providers_accessible"].append(prov)
                result_data["findings"][prov] = provider_findings
                warning(f"{prov} METADATA SERVICE ACCESSIBLE")
            else:
                info(f"{prov} metadata not exposed (good)")

        section("Cloud Metadata Scan Complete")
        if result_data["providers_accessible"]:
            warning(f"Metadata accessible on: {', '.join(result_data['providers_accessible'])}")
            warning("Potential credential exposure — restrict IMDS access")
        else:
            success("No cloud metadata endpoints exposed")

        return result_data
