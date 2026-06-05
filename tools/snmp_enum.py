import socket
import struct
import re
from utils.output import section, info, success, warning, error, result, table


class SNMPEnum:
    description = "Advanced SNMP enumerator: community string brute force, MIB tree walk, interface/user extraction"

    COMMUNITY_STRINGS = ["public", "private", "manager", "admin", "secret", "cisco", "snmp", "read", "write", "all", "hp_admin", "ro", "rw", "snmpd", "default"]

    OIDS = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysServices": "1.3.6.1.2.1.1.7.0",
        "interfaces": "1.3.6.1.2.1.2.2.1.2",
        "ifType": "1.3.6.1.2.1.2.2.1.3",
        "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
        "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
        "ipRouteTable": "1.3.6.1.2.1.4.21.1.1",
        "ipNetToMediaTable": "1.3.6.1.2.1.4.22.1.2",
        "tcpConnTable": "1.3.6.1.2.1.6.13.1.1",
        "udpTable": "1.3.6.1.2.1.7.5.1.1",
        "processTable": "1.3.6.1.2.1.25.1.6",
        "storageTable": "1.3.6.1.2.1.25.2.3.1.1",
        "userTable": "1.3.6.1.4.1.77.1.2.25.1.1",
        "shareTable": "1.3.6.1.4.1.77.1.2.27.1.1",
        "softwareName": "1.3.6.1.2.1.25.6.3.1.2",
        "runningSoftware": "1.3.6.1.2.1.25.4.2.1.2",
    }

    @staticmethod
    def run(target="", host="", community="", walk=False, port=161, timeout=5, threads=5, **kwargs):
        section("SNMP Enumeration")

        target_host = target or host or ""
        if not target_host:
            error("No target host")
            return {"error": "no target"}

        result_data = {
            "target": target_host,
            "communities_found": [],
            "system_info": {},
            "interfaces": [],
            "users": [],
            "routes": [],
            "processes": [],
            "software": [],
        }

        if community:
            communities = [community]
        else:
            communities = SNMPEnum.COMMUNITY_STRINGS

        section("Community String Brute Force")
        for comm in communities:
            if SNMPEnum._snmp_get(target_host, comm, "1.3.6.1.2.1.1.1.0", port, timeout):
                result_data["communities_found"].append(comm)
                success(f"Valid community: '{comm}'")
                community = comm
                break

        if not result_data["communities_found"]:
            error("No valid SNMP community found")
            return result_data

        section("System Information")
        for name, oid in SNMPEnum.OIDS.items():
            if name in ("interfaces", "ifType", "ifSpeed", "ifPhysAddress", "ipRouteTable",
                        "ipNetToMediaTable", "tcpConnTable", "udpTable", "processTable",
                        "storageTable", "userTable", "shareTable", "softwareName", "runningSoftware"):
                continue
            value = SNMPEnum._snmp_get(target_host, community, oid, port, timeout)
            if value:
                result_data["system_info"][name] = value
                result(name, value)

        if walk:
            section("SNMP Tree Walk")
            info("Walking MIB tree for interfaces, users, routes, processes...")

            for if_idx in range(1, 20):
                if_name = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.2.2.1.2.{if_idx}", port, timeout)
                if if_name:
                    if_speed = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.2.2.1.5.{if_idx}", port, timeout)
                    if_mac = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.2.2.1.6.{if_idx}", port, timeout)
                    if_ip = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.4.20.1.1.{if_idx}", port, timeout)
                    if_entry = {"index": if_idx, "name": if_name, "speed": if_speed, "mac": if_mac, "ip": if_ip}
                    result_data["interfaces"].append(if_entry)
                    info(f"Interface {if_idx}: {if_name} ({if_ip or 'no IP'})")

            for uid in range(1, 50):
                user = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.4.1.77.1.2.25.1.1.{uid}", port, timeout)
                if user:
                    result_data["users"].append(user)
                    info(f"User: {user}")

            for pid in range(1, 100):
                proc = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.25.4.2.1.2.{pid}", port, timeout)
                if proc:
                    result_data["processes"].append(proc)

            for sid in range(1, 50):
                sw = SNMPEnum._snmp_get(target_host, community, f"1.3.6.1.2.1.25.6.3.1.2.{sid}", port, timeout)
                if sw:
                    result_data["software"].append(sw)

            if result_data["users"]:
                section("Discovered Users")
                warning(f"Found {len(result_data['users'])} user(s): {', '.join(result_data['users'])}")

            if result_data["processes"]:
                info(f"Found {len(result_data['processes'])} running processes")

            if result_data["software"]:
                info(f"Found {len(result_data['software'])} installed software")

        section("SNMP Enumeration Complete")
        return result_data

    @staticmethod
    def _snmp_get(host, community, oid, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Build SNMP GET request (v1)
            community_bytes = community.encode()
            oid_bytes = SNMPEnum._oid_to_bytes(oid)

            # SNMP packet: version(0) + community + PDU
            pdu = b"\x02\x01\x00" + b"\x04" + bytes([len(community_bytes)]) + community_bytes
            pdu += b"\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
            pdu += b"\x30\x0e\x30\x0c\x06" + bytes([len(oid_bytes)]) + oid_bytes + b"\x05\x00"

            pdu_len = len(pdu)
            packet = b"\x30" + SNMPEnum._len_encode(pdu_len) + pdu

            sock.sendto(packet, (host, port))
            data, addr = sock.recvfrom(65535)
            sock.close()

            # Quick parse: extract string value after 0x04 or 0x02 or 0x40
            i = data.rfind(b"\x04")
            if i > 0 and i + 2 < len(data):
                str_len = data[i+1]
                if i + 2 + str_len <= len(data):
                    return data[i+2:i+2+str_len].decode("utf-8", errors="replace")

            i = data.rfind(b"\x40")
            if i > 0 and i + 2 < len(data):
                str_len = data[i+1]
                if i + 2 + str_len <= len(data):
                    return data[i+2:i+2+str_len].decode("utf-8", errors="replace")

            # Try integer
            i = data.rfind(b"\x02")
            if i > 0:
                return f"INTEGER: {data[i+2]}"

            return str(data[-20:].hex())
        except:
            return None

    @staticmethod
    def _oid_to_bytes(oid):
        parts = [int(x) for x in oid.split(".")]
        result = bytes([parts[0] * 40 + parts[1]])
        for p in parts[2:]:
            if p < 128:
                result += bytes([p])
            else:
                result += bytes([(p >> 7) | 0x80, p & 0x7F])
        return result

    @staticmethod
    def _len_encode(length):
        if length < 128:
            return bytes([length])
        result = []
        while length > 0:
            result.insert(0, length & 0xFF)
            length >>= 8
        return bytes([len(result) | 0x80]) + bytes(result)
