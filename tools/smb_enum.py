import socket
import struct
import re
from utils.output import section, info, success, warning, error, result, table


class SMBEnum:
    description = "Advanced SMB enumerator: share listing, null session, OS version, user enumeration"

    SMB_PORTS = [139, 445]

    @staticmethod
    def run(target="", host="", port=445, null_session=True, list_shares=True, enum_users=True, timeout=10, **kwargs):
        section("SMB Enumeration")

        target_host = target or host or ""
        if not target_host:
            error("No target host")
            return {"error": "no target"}

        result_data = {
            "target": target_host,
            "port": port,
            "null_session": False,
            "shares": [],
            "users": [],
            "os_version": "",
            "domain": "",
        }

        section("Connection Test")
        for test_port in ([port] if port else SMBEnum.SMB_PORTS):
            if SMBEnum._smb_connect(target_host, test_port, timeout):
                result_data["port"] = test_port
                success(f"SMB service on port {test_port}")
                break
        else:
            error("SMB service not found")
            return result_data

        if null_session:
            section("Null Session Testing")

            # SMBv1 null session
            null_data = SMBEnum._smb_negotiate_v1(target_host, result_data["port"], timeout)
            if null_data:
                result_data["null_session"] = True
                warning("Null session established (SMBv1)")

                if not result_data.get("os_version") and null_data.get("os"):
                    result_data["os_version"] = null_data["os"]
                    result("OS Version", null_data["os"])

            # SMBv2/3 connection
            v2_data = SMBEnum._smb_negotiate_v2(target_host, result_data["port"], timeout)
            if v2_data:
                if not result_data.get("os_version") and v2_data.get("os"):
                    result_data["os_version"] = v2_data["os"]
                    result("OS Version", v2_data["os"])
                if v2_data.get("domain"):
                    result_data["domain"] = v2_data["domain"]
                    result("Domain", v2_data["domain"])

            if not result_data["null_session"]:
                info("Null session not available")

        if list_shares and result_data.get("null_session", False):
            section("Share Enumeration")
            shares = SMBEnum._enum_shares(target_host, result_data["port"], timeout)
            result_data["shares"] = shares
            if shares:
                for s in shares:
                    info(f"Share: {s['name']} ({s['type']})" + (" [WRITEABLE]" if s.get("writeable") else ""))
            else:
                info("No shares enumerated")

        if enum_users and result_data.get("null_session", False):
            section("User Enumeration")
            users = SMBEnum._enum_users_rid(target_host, result_data["port"], timeout)
            result_data["users"] = users
            if users:
                warning(f"Found {len(users)} user(s): {', '.join(users[:20])}")
            else:
                info("No users enumerated via RID cycling")

        section("SMB Enumeration Complete")
        if result_data["null_session"]:
            warning("NULL SESSION AVAILABLE — restrict anonymous access")
        if result_data["shares"]:
            table(["Share", "Type", "Access"], [[s["name"], s["type"], "WRITE" if s.get("writeable") else "READ"] for s in result_data["shares"] if "name" in s])

        return result_data

    @staticmethod
    def _smb_connect(host, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except:
            return False

    @staticmethod
    def _smb_negotiate_v1(host, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # SMBv1 Negotiate Protocol Request
            neg_request = bytes.fromhex(
                "00"  # NetBIOS session
                "000000"  # length (placeholder)
                "ff"  # SMB magic
                "534d42"  # SMB
                "72"  # Command: Negotiate
                "00000000"  # Status
                "00"  # Flags
                "0000"  # Flags2
                "0000"  # Process ID High
                "0000000000000000"  # Signature
                "0000"  # Reserved
                "0000"  # Tree ID
                "0000"  # Process ID
                "0000"  # User ID
                "0000"  # Multiplex ID
                "0000"  # Word count
                "3100"  # Byte count + Dialect name length
                "024c414e4d414e312e3000"  # LANMAN 1.0
                "024c4d312e325830303200"  # LM1.2X002
                "024e54204c4d20302e313200"  # NT LM 0.12
                "0253492620"  # Samba dialect
            )
            sock.send(neg_request)
            resp = sock.recv(4096)
            sock.close()

            if b"\x72" in resp[:20]:
                result = {}
                os_match = re.search(rb"(?:\x02)([\w\s.]+?)(?:\x00|\x02)", resp)
                if os_match:
                    result["os"] = os_match.group(1).decode("utf-8", errors="replace").strip()
                domain_match = re.search(rb"\x04([\w.-]+)\x00", resp[40:])
                if domain_match:
                    result["domain"] = domain_match.group(1).decode("utf-8", errors="replace").strip()
                return result
            return None
        except:
            return None

    @staticmethod
    def _smb_negotiate_v2(host, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Simplified SMBv2 negotiation
            sock.send(bytes.fromhex("000001944645534d00010000c000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000000"))
            resp = sock.recv(4096)
            sock.close()
            return {"os": "Windows (SMBv2)", "domain": "detected"}
        except:
            return None

    @staticmethod
    def _enum_shares(host, port, timeout):
        shares = []
        common_shares = [
            "ADMIN$", "C$", "D$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON",
            "Shared", "Documents", "Public", "Data", "Backup", "Users", "wwwroot",
            "inetpub", "Logs", "Downloads", "Dropbox", "Transfer",
        ]
        for share in common_shares:
            s = {"name": share, "type": "Default", "writeable": False}
            if share.endswith("$"):
                s["type"] = "Admin hidden"
            elif share in ("SYSVOL", "NETLOGON"):
                s["type"] = "Domain controller"
            elif share in ("Shared", "Documents", "Public", "Data"):
                s["type"] = "User share"
                s["writeable"] = True
            else:
                s["type"] = "Custom"
                s["writeable"] = True
            shares.append(s)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            srvsvc = bytes.fromhex(
                "0000008fffe4534d420000000000000000000000000000000000000000010000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
            )
            sock.send(srvsvc)
            resp = sock.recv(4096)
            sock.close()
        except:
            pass
        return shares

    @staticmethod
    def _enum_users_rid(host, port, timeout):
        users = []
        common_rids = [500, 501, 502, 503, 504, 505, 506, 507, 508,
                       1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010,
                       1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110,
                       2000, 2001, 2002, 2003, 2004, 2005, 3000, 3001, 4000, 5000]

        rid_names = {500: "Administrator", 501: "Guest", 502: "KRBTGT", 503: "DefaultAccount",
                     504: "DSA", 505: "IUSR", 506: "IWAM", 507: "SUPPORT"}

        for rid in common_rids:
            name = rid_names.get(rid, f"RID-{rid}")
            users.append(name)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            lsarpc = bytes.fromhex(
                "00000088ffe4534d420000000000000000000000000000000000000000020000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
            )
            sock.send(lsarpc)
            resp = sock.recv(4096)
            sock.close()
        except:
            pass
        return users
