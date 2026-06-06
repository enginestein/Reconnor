import socket
import ssl
from datetime import datetime

from utils.output import section, info, success, warning, error, result, table
from utils.external_tools import openssl_check, openssl_test_versions, find_tool


def get_certificate_info(host, port=443, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        cert = ssock.getpeercert()
        ssock.close()
        return cert, None
    except socket.timeout:
        return None, f"Connection to {host}:{port} timed out after {timeout}s"
    except socket.gaierror:
        return None, f"Could not resolve hostname: {host}"
    except ConnectionRefusedError:
        return None, f"Connection refused to {host}:{port}"
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except Exception as e:
        return None, f"Error: {e}"


class SSLChecker:
    name = "ssl"
    description = "Check SSL/TLS certificate information"

    @staticmethod
    def run(target, port=443, ext=False):
        section(f"SSL/TLS Certificate Check: {target}:{port}")

        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.hostname or target

        if ext and find_tool("openssl"):
            section("OpenSSL Deep TLS Analysis")
            openssl_data = openssl_check(target, port)
            if openssl_data:
                for key, val in openssl_data.items():
                    result(key.capitalize(), val)

            supported, unsupported = openssl_test_versions(target, port)
            if supported:
                success(f"Supported: {', '.join(supported)}")
            if unsupported:
                info(f"Unsupported: {', '.join(unsupported)}")

        cert, cert_error = get_certificate_info(target, port)

        if not cert:
            error(f"Could not retrieve certificate for {target}:{port}")
            if cert_error:
                info(f"Reason: {cert_error}")
            return {"target": target, "error": cert_error or "No certificate retrieved"}

        if not ext:
            info("Certificate Information:")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        cn = subject.get("commonName", "N/A")
        result("Common Name", cn)

        org = subject.get("organizationName", "N/A")
        result("Organization", org)

        issuer_cn = issuer.get("commonName", "N/A")
        result("Issuer", issuer_cn)

        not_before = cert.get("notBefore", "N/A")
        not_after = cert.get("notAfter", "N/A")
        result("Valid From", not_before)
        result("Valid Until", not_after)

        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            remaining = expiry - datetime.now()
            days_left = remaining.days
            if days_left < 0:
                error(f"Certificate EXPIRED {abs(days_left)} days ago!")
            elif days_left < 30:
                warning(f"Certificate expires in {days_left} days!")
            elif days_left < 90:
                warning(f"Certificate expires in {days_left} days (recommend renewal)")
            else:
                success(f"Certificate valid for {days_left} more days")
        except:
            pass

        san = cert.get("subjectAltName", [])
        if san:
            section("Subject Alternative Names (SANs)")
            for entry_type, entry_val in san:
                result(entry_type, entry_val)

        if not ext:
            section("TLS Versions Check")
            for ver_name, ver_protocol, ver_desc in [
                ("SSLv2", None, "Insecure - should be disabled"),
                ("SSLv3", None, "Insecure - should be disabled"),
                ("TLSv1.0", ssl.PROTOCOL_TLSv1, "Deprecated - should be disabled"),
                ("TLSv1.1", ssl.PROTOCOL_TLSv1, "Deprecated - should be disabled"),
                ("TLSv1.2", ssl.PROTOCOL_TLS_SERVER, "Secure - should be enabled"),
                ("TLSv1.3", ssl.PROTOCOL_TLS_SERVER, "Secure - should be enabled"),
            ]:
                info(f"  {ver_name}: checking not fully supported in basic mode")

        info(f"\nCertificate details for {target}:{port} retrieved successfully")
        return {"target": target, "port": port, "subject": subject, "issuer": issuer, "san": san}
