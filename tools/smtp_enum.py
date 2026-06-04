import socket
import smtplib
import dns.resolver
from utils.output import section, info, success, warning, error, result


class SMTPEnum:
    name = "smtp"
    description = "SMTP server enumeration and email validation"

    @staticmethod
    def run(target, timeout=10, port=25):
        section(f"SMTP Enumeration: {target}")

        domain = target.strip().lower()
        if domain.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        mx_records = []
        info(f"Resolving MX records for {domain}...")
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = [(int(r.preference), str(r.exchange).rstrip(".")) for r in answers]
            mx_records.sort()
            success(f"Found {len(mx_records)} MX record(s)")
            for pref, mx in mx_records:
                result(f"  [{pref}]", mx)
        except dns.resolver.NoAnswer:
            warning("No MX records found")
        except dns.resolver.NXDOMAIN:
            error("Domain does not exist")
            return {"target": domain, "mx": [], "open_relay": False, "smtp_commands": []}
        except ImportError:
            error("dnspython not installed. Install with: pip install dnspython")
            return {"target": domain, "mx": [], "open_relay": False, "smtp_commands": []}

        if not mx_records:
            return {"target": domain, "mx": [], "open_relay": False, "smtp_commands": []}

        section("SMTP Server Testing")
        mx_host = mx_records[0][1]
        info(f"Testing SMTP server: {mx_host}:{port}")

        commands_supported = []
        open_relay = False
        banner = ""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((mx_host, port))

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result("Banner", banner.split("\n")[0] if banner else "None")

            sock.sendall(b"EHLO test.com\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            for line in resp.split("\r\n"):
                line = line.strip()
                if line and line[0].isdigit():
                    cmd = line.split()[1] if len(line.split()) > 1 else ""
                    if cmd and cmd.isalpha():
                        commands_supported.append(cmd)

            commands_str = ", ".join(commands_supported) if commands_supported else "None"
            result("SMTP Commands", commands_str)

            if "EXPN" in commands_supported:
                sock.sendall(b"EXPN root\r\n")
                expn_resp = sock.recv(1024).decode("utf-8", errors="ignore")
                info(f"EXPN root response: {expn_resp.strip()[:100]}")
            if "VRFY" in commands_supported:
                sock.sendall(b"VRFY root\r\n")
                vrfy_resp = sock.recv(1024).decode("utf-8", errors="ignore")
                info(f"VRFY root response: {vrfy_resp.strip()[:100]}")

            sock.sendall(b"MAIL FROM:<test@test.com>\r\n")
            mail_resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall(b"RCPT TO:<test@" + domain.encode() + b">\r\n")
            rcpt_resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall(b"DATA\r\n")
            data_resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall(b"QUIT\r\n")

            if "250" in mail_resp and "250" in rcpt_resp:
                warning("Server accepts mail relay - possible open relay!")
                open_relay = True

            sock.close()
        except socket.timeout:
            warning(f"Connection to {mx_host}:{port} timed out")
        except ConnectionRefusedError:
            warning(f"Connection refused by {mx_host}:{port}")
        except Exception as e:
            error(f"SMTP error: {e}")

        section("SMTP Enumeration Results")
        if open_relay:
            warning("OPEN RELAY DETECTED - Server accepts mail from external domains!")
        else:
            success("Server is not an open relay")

        result("MX Host", mx_host)
        result("Port", str(port))
        result("Banner", banner.split("\n")[0] if banner else "None")
        result("Commands", ", ".join(commands_supported) if commands_supported else "None")
        result("Open Relay", "YES" if open_relay else "No")

        return {
            "target": domain,
            "mx": mx_records,
            "primary_mx": mx_host,
            "banner": banner,
            "smtp_commands": commands_supported,
            "open_relay": open_relay,
        }
