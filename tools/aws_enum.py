import json
import urllib.request
import socket
import re
from utils.output import section, info, success, warning, error, result, table


class AWSEnum:
    description = "Advanced AWS enumeration: IAM, S3, EC2, metadata, STS assume-role testing"

    AWS_ENDPOINTS = {
        "s3": "s3.amazonaws.com",
        "iam": "iam.amazonaws.com",
        "sts": "sts.amazonaws.com",
        "ec2": "ec2.amazonaws.com",
    }

    METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/public-keys/",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ]

    COMMON_BUCKET_NAMES = [
        "backup", "logs", "data", "uploads", "assets", "media", "static",
        "images", "files", "docs", "config", "source", "archive", "export",
        "import", "transfer", "private", "public", "internal", "dev", "test",
        "stage", "prod", "temp", "tmp", "cache", "content", "download",
    ]

    @staticmethod
    def run(target="", bucket="", metadata=False, s3_check=False, iam_check=False, ec2_check=False, sts_check=False, timeout=10, threads=20, **kwargs):
        section("AWS Enumeration")

        result_data = {
            "target": target or "",
            "metadata": {"accessible": False, "data": {}},
            "s3_buckets": {"accessible": [], "inaccessible": []},
            "iam": {},
            "ec2": {},
            "sts": {},
        }

        if metadata:
            section("EC2 Metadata Service")
            for url in AWSEnum.METADATA_URLS:
                try:
                    req = urllib.request.Request(url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace").strip()
                        if body:
                            result_data["metadata"]["accessible"] = True
                            result_data["metadata"]["data"][url] = body[:200]
                            if "iam" in url.lower() or "security" in url.lower():
                                warning(f"EC2 METADATA: {url}")
                                success(f"Data: {body[:200]}")
                            else:
                                info(f"Metadata: {url} -> {body[:100]}")
                except:
                    pass

            if result_data["metadata"]["accessible"]:
                warning("EC2 METADATA SERVICE ACCESSIBLE — potential credential exposure")
            else:
                success("EC2 metadata service not exposed")

        if s3_check:
            section("S3 Bucket Enumeration")
            bucket_names = []
            if bucket:
                bucket_names.append(bucket)
            if target:
                domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(".")[0]
                for suffix in AWSEnum.COMMON_BUCKET_NAMES:
                    bucket_names.append(f"{domain}-{suffix}")
                    bucket_names.append(f"{suffix}-{domain}")
                    bucket_names.append(f"{domain}{suffix}")
                bucket_names.append(domain)

            for bname in set(bucket_names):
                bucket_url = f"https://{bname}.s3.amazonaws.com"
                try:
                    req = urllib.request.Request(bucket_url)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        if resp.status == 200:
                            result_data["s3_buckets"]["accessible"].append(bname)
                            success(f"S3 bucket accessible: {bname}")
                        elif resp.status == 301:
                            result_data["s3_buckets"]["accessible"].append(bname)
                            success(f"S3 bucket exists (redirect): {bname}")
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        result_data["s3_buckets"]["accessible"].append(bname)
                        info(f"S3 bucket exists (forbidden): {bname}")
                    else:
                        result_data["s3_buckets"]["inaccessible"].append(bname)
                except:
                    result_data["s3_buckets"]["inaccessible"].append(bname)

            if result_data["s3_buckets"]["accessible"]:
                warning(f"Found {len(result_data['s3_buckets']['accessible'])} S3 bucket(s)")
                for b in result_data["s3_buckets"]["accessible"]:
                    info(f"  https://{b}.s3.amazonaws.com")

        if iam_check:
            section("IAM Check")
            # Test common IAM endpoints
            iam_tests = {
                "GetUser": "Action=GetUser&Version=2010-05-08",
                "ListUsers": "Action=ListUsers&Version=2010-05-08",
                "ListRoles": "Action=ListRoles&Version=2010-05-08",
            }
            for test_name, params in iam_tests.items():
                try:
                    url = f"https://iam.amazonaws.com/?{params}"
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        if resp.status == 200:
                            result_data["iam"][test_name] = "accessible"
                            warning(f"IAM {test_name} accessible")
                            break
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        info(f"IAM {test_name}: AccessDenied (good)")
                        break
                except:
                    pass
            else:
                success("IAM API not directly accessible (expected outside EC2)")

        if sts_check:
            section("STS Check")
            try:
                url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        result_data["sts"]["caller_identity"] = "accessible"
                        warning("STS GetCallerIdentity accessible")
            except:
                info("STS API not accessible")

        section("AWS Enumeration Complete")
        if result_data["metadata"]["accessible"]:
            warning("CLOUD METADATA EXPOSED — restrict IMDS access")
        if result_data["s3_buckets"]["accessible"]:
            warning(f"{len(result_data['s3_buckets']['accessible'])} S3 bucket(s) found — check for public access")

        return result_data
