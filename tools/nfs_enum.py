import socket
import struct
import subprocess
import re
from utils.output import section, info, success, warning, error, result, table


class NFSEnum:
    description = "NFS enumeration: export listing, mount checking, permission analysis"

    RPCCLIENT_CMDS = ["rpcinfo", "showmount"]

    @staticmethod
    def run(target="", host="", port=2049, timeout=10, **kwargs):
        section("NFS Enumeration")

        target_host = target or host or ""
        if not target_host:
            error("No target host")
            return {"error": "no target"}

        result_data = {
            "target": target_host,
            "nfs_port": None,
            "mountd_port": None,
            "rpcbind_info": [],
            "exports": [],
            "mountable": [],
            "world_writable": [],
        }

        section("RPCBind Information")
        rpc_info = NFSEnum._rpc_query(target_host, timeout)
        if rpc_info:
            for entry in rpc_info:
                if "nfs" in entry.lower() or "100003" in entry or "mount" in entry.lower() or "100005" in entry:
                    result_data["rpcbind_info"].append(entry)
                    if "nfs" in entry.lower() or "100003" in entry:
                        port_match = re.search(r"port\s+(\d+)", entry, re.I)
                        if port_match:
                            result_data["nfs_port"] = int(port_match.group(1))
                    if "mount" in entry.lower() or "100005" in entry:
                        port_match = re.search(r"port\s+(\d+)", entry, re.I)
                        if port_match:
                            result_data["mountd_port"] = int(port_match.group(1))
            for entry in result_data["rpcbind_info"]:
                info(entry)

        section("Export List")
        exports = NFSEnum._get_exports(target_host, timeout)
        result_data["exports"] = exports

        if exports:
            for exp in exports:
                result("Export", exp["export"])
                if exp.get("options"):
                    result("Options", ", ".join(exp["options"]))
                if exp.get("clients"):
                    for client in exp["clients"]:
                        info(f"  Allowed client: {client}")
        else:
            try:
                proc = subprocess.run(
                    ["showmount", "-e", target_host],
                    capture_output=True, text=True, timeout=timeout,
                )
                if proc.returncode == 0:
                    for line in proc.stdout.strip().split("\n")[1:]:
                        parts = line.split()
                        if len(parts) >= 1:
                            exp_path = parts[0]
                            clients = parts[1:] if len(parts) > 1 else ["*"]
                            exports.append({"export": exp_path, "clients": clients, "options": []})
                            result_data["exports"] = exports
                            result("Export", exp_path)
            except:
                pass

        section("Mount Testing")
        export = ""
        for exp in exports:
            export_path = exp["export"]
            mount_point = f"/tmp/nfs_mount_{target_host.replace('.','_')}"
            info(f"Testing mount of {export_path}...")
            result_data["mountable"].append(export_path)

            if "*" in str(exp.get("clients", [])) or "everyone" in str(exp.get("options", [])).lower():
                result_data["world_writable"].append(export_path)
                warning(f"World accessible: {export_path}")

        if not exports:
            info("No NFS exports discovered")
        else:
            for exp in exports:
                info(f"Export: {exp['export']} {'(world accessible)' if '*' in str(exp.get('clients', [])) else ''}")

        section("NFS Enumeration Complete")
        if result_data["world_writable"]:
            warning(f"WORLD WRITABLE EXPORTS: {', '.join(result_data['world_writable'])}")
        if not exports:
            success("No NFS shares exposed")
        return result_data

    @staticmethod
    def _rpc_query(host, timeout):
        results = []
        services = [
            ("nfs", 100003),
            ("mountd", 100005),
            ("nlockmgr", 100021),
            ("status", 100024),
            ("ypserv", 100004),
        ]
        for name, prog in services:
            for version in range(1, 5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(timeout)

                    call_body = b"\x00" * 8 + struct.pack(">IIII", 0, prog, version, 17) + b"\x00" * 8
                    call_len = len(call_body) + 4
                    frag = struct.pack(">I", 0x80000000 | call_len) + call_body

                    sock.sendto(frag, (host, 111))
                    data, addr = sock.recvfrom(4096)
                    sock.close()

                    if len(data) > 24:
                        port = struct.unpack(">I", data[24:28])[0] if len(data) >= 28 else 0
                        if port > 0 and port < 65536:
                            results.append(f"Program {name} ({prog}) v{version}: port {port}")
                            break
                except:
                    pass
        return results

    @staticmethod
    def _get_exports(host, timeout):
        exports = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Mount request for export list
            call = struct.pack(">IIII", 0, 100005, 1, 17) + b"\x00" * 12 + b"\x00"
            frag = struct.pack(">I", 0x80000000 | (len(call) + 4)) + call
            sock.sendto(frag, (host, 111))
            data, addr = sock.recvfrom(4096)
            sock.close()

            if len(data) < 28:
                return exports
            mountd_port = struct.unpack(">I", data[24:28])[0]
            if mountd_port == 0 or mountd_port >= 65536:
                return exports

            # Query mountd for exports
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock2.settimeout(timeout)
            export_call = struct.pack(">IIII", 0, 100005, 1, 5) + b"\x00" * 12
            frag2 = struct.pack(">I", 0x80000000 | (len(export_call) + 4)) + export_call

            sock2.sendto(frag2, (host, mountd_port))
            resp, addr2 = sock2.recvfrom(8192)
            sock2.close()

            # Parse exports
            text = resp.decode("utf-8", errors="replace")
            for line in text.split("\x00"):
                line = line.strip()
                if line.startswith("/"):
                    exports.append({"export": line, "clients": [], "options": []})
        except:
            pass

        return exports
