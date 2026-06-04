import socket
import requests
from utils.output import section, info, success, warning, error, result, table


def get_ip_info(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
            else:
                return None
    except:
        pass
    return None


def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_own_ip():
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("ip")
    except:
        pass
    return None


class IPGeolocator:
    name = "geoip"
    description = "Geolocate an IP address or domain"

    @staticmethod
    def run(target):
        section(f"IP Geolocator: {target}")

        if target.lower() in ["me", "my", "self", "own"]:
            ip = get_own_ip()
            if ip:
                success(f"Your public IP: {ip}")
                target = ip
            else:
                error("Could not determine your public IP")
                return {"target": target, "error": "Could not determine public IP"}

        if not target.replace(".", "").isdigit():
            ip = get_ip_from_domain(target)
            if ip:
                info(f"Resolved {target} -> {ip}")
                target = ip
            else:
                error(f"Could not resolve {target}")
                return {"target": target, "error": "DNS resolution failed"}

        info(f"Looking up geolocation for {target}...")

        data = get_ip_info(target)
        if not data:
            try:
                data = requests.get(
                    f"https://ipinfo.io/{target}/json",
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0"}
                ).json()
                if data:
                    section(f"Geolocation Results for {target}")
                    result("IP", data.get("ip", target))
                    result("Hostname", data.get("hostname", "N/A"))
                    result("City", data.get("city", "N/A"))
                    result("Region", data.get("region", "N/A"))
                    result("Country", data.get("country", "N/A"))
                    loc = data.get("loc", "")
                    if loc:
                        result("Coordinates", loc)
                    result("Org", data.get("org", "N/A"))
                    result("Postal", data.get("postal", "N/A"))
                    result("Timezone", data.get("timezone", "N/A"))
                    return {"target": target, "data": data}
            except:
                pass

        if not data:
            error(f"Could not geolocate {target}")
            return {"target": target, "error": "Geolocation lookup failed"}

        section(f"Geolocation Results for {target}")
        result("IP", data.get("query", target))
        result("ISP", data.get("isp", data.get("org", "N/A")))
        result("Organization", data.get("org", "N/A"))
        result("City", data.get("city", "N/A"))
        result("Region", data.get("regionName", "N/A"))
        result("Country", data.get("country", "N/A"))
        result("Country Code", data.get("countryCode", "N/A"))
        result("ZIP", data.get("zip", "N/A"))
        result("Latitude", str(data.get("lat", "N/A")))
        result("Longitude", str(data.get("lon", "N/A")))
        result("Timezone", data.get("timezone", "N/A"))
        result("AS Number", data.get("as", "N/A"))
        result("Mobile", str(data.get("mobile", "N/A")))
        result("Proxy", str(data.get("proxy", "N/A")))

        if data.get("lat") and data.get("lon"):
            lat = data["lat"]
            lon = data["lon"]
            info(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")

        return {"target": target, "data": data}
