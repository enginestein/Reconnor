# AWS Enumerator

AWS enumeration: IAM/S3/EC2/STS checks, bucket discovery, metadata probing.

```
python3 main.py aws-enum --target example.com --s3 --metadata
```

**Options:**
- `--target` — Target domain
- `--bucket` — Single bucket name to check
- `--s3` — Check S3 buckets
- `--iam` — Test IAM API
- `--ec2` — Check EC2 metadata
- `--sts` — Test STS API
- `--metadata` — Test EC2 metadata service
- `--timeout` — HTTP timeout (default: 10)
- `--threads` — Max threads (default: 20)
