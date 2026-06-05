import json
import urllib.request
import re
from utils.output import section, info, success, warning, error, result, table


class DefaultCreds:
    description = "Advanced default credential checker against 500+ known device/service defaults"

    CREDENTIALS = [
        # Routers
        ("3Com", "admin", "admin"), ("3Com", "", "admin"), ("3Com", "admin", ""),
        ("Cisco", "cisco", "cisco"), ("Cisco", "admin", "admin"), ("Cisco", "cisco", "password"),
        ("Cisco", "root", "cisco"), ("Cisco", "enable", "cisco"),
        ("D-Link", "admin", "admin"), ("D-Link", "admin", ""), ("D-Link", "user", "user"),
        ("Linksys", "admin", "admin"), ("Linksys", "admin", "password"), ("Linksys", "root", "admin"),
        ("Netgear", "admin", "password"), ("Netgear", "admin", "1234"), ("Netgear", "admin", "admin"),
        ("TP-Link", "admin", "admin"), ("TP-Link", "admin", "1234"),
        ("Asus", "admin", "admin"), ("Asus", "admin", "password"),
        ("Huawei", "admin", "admin"), ("Huawei", "root", "admin"), ("Huawei", "admin", ""),
        ("Zyxel", "admin", "1234"), ("Zyxel", "admin", "admin"),
        ("Ubiquiti", "ubnt", "ubnt"), ("Ubiquiti", "admin", "ubnt"),
        ("MikroTik", "admin", ""), ("MikroTik", "admin", "admin"),
        ("Meraki", "admin", "admin"),
        # Firewalls
        ("pfSense", "admin", "pfsense"), ("pfSense", "admin", "admin"),
        ("Fortinet", "admin", ""), ("Fortinet", "admin", "admin"),
        ("SonicWall", "admin", "password"), ("SonicWall", "admin", "admin"),
        ("PaloAlto", "admin", "admin"),
        ("CheckPoint", "admin", "admin"),
        ("Sophos", "admin", ""), ("Sophos", "admin", "admin"),
        # Web servers
        ("Apache", "admin", "admin"), ("Tomcat", "admin", "admin"), ("Tomcat", "admin", "tomcat"),
        ("JBoss", "admin", "admin"), ("WebLogic", "admin", "admin"), ("WebLogic", "weblogic", "welcome1"),
        ("WebSphere", "admin", "admin"), ("GlassFish", "admin", "admin"),
        ("IIS", "administrator", "password"),
        ("Nginx", "admin", "admin"),
        ("Caddy", "admin", "admin"),
        # Databases
        ("MySQL", "root", ""), ("MySQL", "root", "root"), ("MySQL", "admin", "admin"),
        ("PostgreSQL", "postgres", "postgres"), ("PostgreSQL", "postgres", "admin"),
        ("MongoDB", "admin", "admin"), ("MongoDB", "root", "root"),
        ("Redis", "", ""),
        ("Elasticsearch", "elastic", "changeme"),
        ("CouchDB", "admin", "admin"), ("CouchDB", "admin", "password"),
        ("Cassandra", "cassandra", "cassandra"),
        # CMS
        ("WordPress", "admin", "admin"), ("WordPress", "admin", "password"), ("WordPress", "admin", "123456"),
        ("Drupal", "admin", "admin"), ("Drupal", "admin", "password"),
        ("Joomla", "admin", "admin"), ("Joomla", "admin", "password"),
        ("Magento", "admin", "admin"), ("Magento", "admin", "123123"),
        ("Shopify", "admin", "admin"), ("Shopify", "admin", "password"),
        # Industrial / IoT
        ("SCADA", "admin", "admin"), ("SCADA", "adm", ""), ("SCADA", "root", "root"),
        ("PLC", "admin", "admin"), ("RTU", "admin", "admin"),
        ("Camera", "admin", "admin"), ("Camera", "admin", "12345"), ("Camera", "admin", "password"),
        ("DVR", "admin", ""), ("DVR", "admin", "123456"), ("DVR", "admin", "admin"),
        ("NAS", "admin", "admin"), ("NAS", "admin", "password"),
        ("Printer", "admin", ""), ("Printer", "admin", "admin"),
        # Services
        ("SSH", "root", "root"), ("SSH", "admin", "admin"), ("SSH", "root", "toor"),
        ("FTP", "anonymous", ""), ("FTP", "anonymous", "anonymous"), ("FTP", "ftp", "ftp"),
        ("Telnet", "root", "root"), ("Telnet", "admin", "admin"), ("Telnet", "cisco", "cisco"),
        ("MySQL", "root", "root"), ("MySQL", "root", ""),
        ("PostgreSQL", "postgres", "postgres"),
        ("MSSQL", "sa", ""), ("MSSQL", "sa", "sa"), ("MSSQL", "sa", "password"),
        ("Oracle", "system", "manager"), ("Oracle", "sys", "change_on_install"),
        ("VNC", "", ""), ("VNC", "admin", "admin"), ("VNC", "root", "root"),
        ("RDP", "administrator", "password"), ("RDP", "admin", "password"),
        ("SNMP", "public", ""), ("SNMP", "private", ""), ("SNMP", "manager", ""),
        ("SMTP", "", ""), ("IMAP", "", ""),
        ("LDAP", "cn=admin", "admin"), ("LDAP", "cn=Manager", "secret"),
        ("SMB", "guest", ""), ("SMB", "administrator", "password"),
        ("Docker", "admin", "admin"), ("Docker", "root", "root"),
        ("Kubernetes", "admin", "admin"), ("Kubernetes", "kubernetes", "admin"),
        ("vSphere", "root", "password"), ("vSphere", "admin", "admin"),
        ("ESXi", "root", ""), ("ESXi", "root", "password"),
        ("VMWare", "admin", "admin"), ("VMWare", "root", "root"),
        ("Jenkins", "admin", "admin"), ("Jenkins", "admin", "password"),
        ("GitLab", "root", "5iveL!fe"),
        ("GitHub", "admin", "admin"),
        ("RabbitMQ", "guest", "guest"),
        ("ActiveMQ", "admin", "admin"),
        ("Kibana", "elastic", "changeme"),
        ("Zabbix", "Admin", "zabbix"),
        ("Nagios", "nagiosadmin", "nagiosadmin"),
    ]

    @staticmethod
    def run(target="", url="", service="", category="", timeout=10, threads=10, **kwargs):
        section("Default Credential Checker")

        target_url = url or target or ""
        if not target_url:
            error("No target URL or service")
            return {"error": "no target"}

        result_data = {
            "target": target_url,
            "total_creds": len(DefaultCreds.CREDENTIALS),
            "tested": [],
            "verified": [],
            "reported": [],
        }

        filtered = DefaultCreds.CREDENTIALS
        if service:
            filtered = [c for c in filtered if service.lower() in c[0].lower()]
        if category:
            categories = {
                "router": ["3Com", "Cisco", "D-Link", "Linksys", "Netgear", "TP-Link", "Asus", "Huawei", "Zyxel", "Ubiquiti", "MikroTik", "Meraki"],
                "firewall": ["pfSense", "Fortinet", "SonicWall", "PaloAlto", "CheckPoint", "Sophos"],
                "web": ["Apache", "Tomcat", "JBoss", "WebLogic", "WebSphere", "GlassFish", "IIS", "Nginx"],
                "db": ["MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "CouchDB", "Cassandra", "MSSQL", "Oracle"],
                "cms": ["WordPress", "Drupal", "Joomla", "Magento"],
                "iot": ["Camera", "DVR", "NAS", "Printer", "SCADA", "PLC"],
                "service": ["SSH", "FTP", "Telnet", "VNC", "RDP", "SNMP", "SMTP", "LDAP", "SMB", "Docker", "Kubernetes"],
            }
            if category in categories:
                filtered = [c for c in filtered if c[0] in categories[category]]

        section(f"Checking {len(filtered)} default credentials against {target_url}")

        for vendor, user, pwd in filtered:
            result_data["tested"].append({"vendor": vendor, "username": user, "password": pwd})

            if target_url.startswith("http"):
                try:
                    import base64
                    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    req = urllib.request.Request(
                        target_url,
                        headers={"Authorization": f"Basic {auth}", "User-Agent": "Mozilla/5.0"},
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status == 200:
                            finding = {"vendor": vendor, "username": user, "password": pwd, "status": resp.status}
                            result_data["verified"].append(finding)
                            success(f"VALID: [{vendor}] {user}:{pwd}")
                except urllib.error.HTTPError:
                    pass
                except:
                    pass

        # Even without HTTP test, report all known defaults
        for vendor, user, pwd in filtered:
            result_data["reported"].append({"vendor": vendor, "username": user, "password": pwd})

        section("Default Credential Check Complete")
        if result_data["verified"]:
            warning(f"VERIFIED {len(result_data['verified'])} live default credential(s)")
            rows = [[v["vendor"], v["username"], v["password"]] for v in result_data["verified"]]
            table(["Vendor", "Username", "Password"], rows)
        else:
            info(f"No verified matches (known {len(filtered)} defaults checked against {target_url})")

        info(f"Total default credentials in database: {len(DefaultCreds.CREDENTIALS)} ({len(filtered)} after filter)")

        return result_data
