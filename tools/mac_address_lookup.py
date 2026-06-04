import re
import requests
from utils.output import section, info, success, warning, error, result

OUI_DB_URL = "https://raw.githubusercontent.com/ai-rob/oui-db/master/oui.txt"

def load_oui_cache():
    try:
        resp = requests.get(OUI_DB_URL, timeout=15)
        if resp.status_code == 200:
            oui_map = {}
            for line in resp.text.splitlines():
                match = re.match(r'^([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$', line)
                if match:
                    oui_key = match.group(1).replace("-", ":").upper()
                    oui_map[oui_key] = match.group(2).strip()
                match2 = re.match(r'^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$', line)
                if match2:
                    oui_map[match2.group(1).upper()] = match2.group(2).strip()
            info(f"Loaded {len(oui_map)} OUI entries")
            return oui_map
    except Exception as e:
        warning(f"Could not load OUI database: {e}")
    return None

def lookup_mac_via_api(mac):
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return None

def normalize_mac(mac):
    clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
    if len(clean) < 6:
        return None
    return clean.upper()

class MACLookup:
    name = "mac-address"
    description = "Look up MAC address vendor/OUI information"

    @staticmethod
    def run(target):
        section(f"MAC Address Lookup: {target}")

        normalized = normalize_mac(target)
        if not normalized:
            error(f"Invalid MAC address: {target}")
            return {"target": target, "error": "Invalid MAC format"}

        oui_prefix = normalized[:6]
        oui_display = ":".join(oui_prefix[i:i+2] for i in range(0, 6, 2))

        info(f"OUI prefix: {oui_display}")

        vendor = lookup_mac_via_api(oui_display)
        if vendor:
            success(f"Vendor: {vendor}")
        else:
            oui_cache = load_oui_cache()
            if oui_cache:
                vendor = oui_cache.get(oui_prefix) or oui_cache.get(oui_display)
            if vendor:
                success(f"Vendor: {vendor}")
            else:
                warning("Vendor not found in database")
                if len(normalized) == 12:
                    info("Full MAC is a unicast address - vendor may be unregistered or the database is stale")

        info(f"MAC type: {'Multicast' if int(normalized[:2], 16) & 1 else 'Unicast'}")
        info(f"Address: {'Locally administered' if int(normalized[:2], 16) & 2 else 'Globally unique (OUICertified)'}")

        return {"target": target, "vendor": vendor, "oui": oui_prefix}
