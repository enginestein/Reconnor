import socket
import struct
import re
from utils.output import section, info, success, warning, error, result, table


class RPCEnum:
    description = "Advanced RPC enumerator: endpoint mapper, service discovery via rpcdump"

    RPCBIND_PORT = 111

    WELL_KNOWN_PROGRAMS = {
        100000: "PMAP", 100001: "STATS", 100002: "RSTATS", 100003: "NFS",
        100004: "YPSERV", 100005: "MOUNT", 100006: "DBX", 100007: "YPBIND",
        100008: "WALL", 100009: "YPPASSWD", 100010: "ETHERSTAT", 100011: "RQUOTA",
        100012: "RUSER", 100013: "RUSERS", 100014: "RSTAT", 100015: "RSTAT",
        100016: "SPRAY", 100017: "YPUPD", 100018: "YPPOLL", 100019: "YPXFR",
        100020: "YPSERV", 100021: "NLOCKMGR", 100022: "SHOWFH", 100023: "YPOLD",
        100024: "STATUS", 100026: "KEYSERV", 100027: "YPBIND", 100028: "YPUPD",
        100029: "RPC.METADIR", 100030: "RPC.METADIR", 100031: "RPC.IO",
        100033: "RPC.NFS", 100035: "RPC.MOUNT", 100037: "RPC.NLOCKMGR",
        100038: "RPC.STATD", 100039: "RPC.RQUOTA", 100040: "RPC.SPRAYD",
        100041: "RPC.STATD", 100042: "RPC.METADIR", 100043: "RPC.NFS",
        100044: "RPC.MOUNT", 100045: "RPC.NLOCKMGR", 100046: "RPC.STATD",
        100047: "RPC.RQUOTA", 100048: "RPC.SPRAYD", 100049: "RPC.STATD",
        100051: "PCNFS", 100052: "FTP", 100053: "RPC.METADIR", 100055: "NFS_ACL",
        100059: "SAM", 100060: "RASS", 100061: "RPC.MOUNT", 100062: "RPC.NLOCKMGR",
        100065: "RPC.STATD", 100068: "RPC.METADIR", 100069: "RPC.NFS",
        100071: "RPC.NLOCKMGR", 100078: "RPC.KEYSERV", 100079: "RPC",
        100080: "NFS", 100083: "RPC.METADIR", 100085: "NFS_ACL",
        100087: "RPC.MOUNT", 100088: "RPC.NLOCKMGR", 100089: "RPC",
        100090: "RPC.STATD", 100092: "RPC.IO", 100093: "RPC",
        100100: "RPC.METADIR", 100101: "RPC", 100102: "RPC",
        100103: "RPC", 100104: "RPC", 100105: "RPC",
        100106: "RPC", 100107: "RPC", 100108: "RPC",
        100109: "RPC", 100110: "RPC", 100111: "RPC",
        100112: "RPC", 100113: "RPC", 100114: "RPC",
        100115: "RPC", 100116: "RPC", 100117: "RPC",
        100118: "RPC", 100119: "RPC", 100120: "RPC",
        100121: "RPC", 100122: "RPC", 100123: "RPC",
        100124: "RPC", 100125: "RPC", 100126: "RPC",
        100127: "RPC", 100128: "RPC", 100129: "RPC",
        100130: "RPC", 100131: "RPC", 100132: "RPC",
        100133: "RPC.SM", 100134: "RPC.SM", 100135: "RPC.SM",
        100136: "RPC.SM", 100137: "RPC.SM", 100138: "RPC.SM",
        100139: "RPC.SM", 100140: "RPC.SM", 100141: "RPC.SM",
        100142: "RPC.SM", 100143: "RPC.SM", 100144: "RPC.SM",
        100145: "RPC.SM", 100146: "RPC.SM", 100147: "RPC.SM",
        100148: "RPC.SM", 100149: "RPC.SM", 100150: "RPC.SM",
        100151: "RPC.SM", 100152: "RPC.SM", 100153: "RPC.SM",
        100154: "RPC.SM", 100155: "RPC.SM", 100156: "RPC",
        200000: "RQUOTA", 200001: "NFS", 200002: "MOUNT",
        300000: "RPC.KEYSERV", 300001: "RPC.METADIR",
        390000: "SUN_FSS", 390100: "SUN_NFS4",
        536870912: "STATUS", 536870913: "STATUS",
    }

    @staticmethod
    def run(target="", host="", port=111, timeout=10, **kwargs):
        section("RPC Enumeration")

        target_host = target or host or ""
        if not target_host:
            error("No target host")
            return {"error": "no target"}

        result_data = {
            "target": target_host,
            "port": port,
            "services": [],
            "unusual_ports": [],
        }

        section("RPC Endpoint Mapper Dump")
        services = RPCEnum._rpcdump(target_host, port, timeout)

        if not services:
            info("No RPC services discovered via portmapper (try --port 111)")

        result_data["services"] = services

        if services:
            table(
                ["Program", "Version", "Protocol", "Port", "Service"],
                [[s["program"], str(s["version"]), s["protocol"], str(s["port"]), s["service_name"]] for s in services]
            )

            unusual = [s for s in services if s["port"] < 1024 and s["port"] not in (111, 2049, 22, 80, 443, 3306, 5432, 6379, 8080)]
            if unusual:
                result_data["unusual_ports"] = unusual
                warning(f"Unusual privileged ports detected: {', '.join(str(s['port']) for s in unusual)}")

        if services:
            for s in services:
                srv = s["service_name"]
                if srv in ("NFS", "MOUNT", "NLOCKMGR", "STATUS"):
                    info(f"{srv} on port {s['port']} ({s['protocol']})")
                elif srv in ("YPSERV", "YPBIND", "YPUPD", "YPPASSWD"):
                    info(f"NIS service: {srv} on port {s['port']}")
                elif srv in ("SAM", "PCNFS", "RSTATS"):
                    info(f"Auth service: {srv} on port {s['port']}")

        section("RPC Enumeration Complete")
        return result_data

    @staticmethod
    def _rpcdump(host, port, timeout):
        services = []
        for prog_num, prog_name in sorted(RPCEnum.WELL_KNOWN_PROGRAMS.items()):
            for version in range(1, 5):
                for protocol, proto_num in [("TCP", 6), ("UDP", 17)]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto_num == 17 else socket.SOCK_STREAM)
                        sock.settimeout(timeout)

                        # RPC call
                        call = struct.pack(">IIII", 0, prog_num, version, proto_num) + b"\x00" * 16
                        msg = struct.pack(">I", 0x80000000 | (len(call) + 4)) + call

                        sock.sendto(msg, (host, port))
                        data, addr = sock.recvfrom(4096)
                        sock.close()

                        if len(data) >= 28:
                            svc_port = struct.unpack(">I", data[24:28])[0]
                            if svc_port > 0 and svc_port < 65536:
                                entry = {
                                    "program": str(prog_num),
                                    "version": version,
                                    "protocol": "TCP" if proto_num == 6 else "UDP",
                                    "port": svc_port,
                                    "service_name": prog_name,
                                }
                                if entry not in services:
                                    services.append(entry)
                                    break  # One version is enough
                    except:
                        pass
        return services
