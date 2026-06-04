import re
import requests
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table

MESSAGING_APPS = [
    ("Telegram", "https://t.me/{number}", "Telegram profile"),
    ("WhatsApp", "https://wa.me/{number}", "WhatsApp link"),
    ("Signal", "https://signal.me/#p/{number}", "Signal link"),
    ("Viber", "viber://chat?number={number}", "Viber chat (app only)"),
    ("WeChat", "https://weixin.qq.com/", "WeChat (no direct URL)"),
    ("Line", "https://line.me/ti/p/~{number}", "Line add"),
    ("KakaoTalk", "https://kakaotalk.com/", "Kakao (no direct URL)"),
]

SOCIAL_SEARCH_PATTERNS = [
    ("Facebook", "https://www.facebook.com/search/top/?q={number}", False),
    ("Twitter/X", "https://twitter.com/search?q={number}&f=user", False),
    ("LinkedIn", "https://www.linkedin.com/search/results/people/?keywords={number}", False),
    ("Instagram", "https://www.instagram.com/web/search/topsearch/?query={number}", False),
    ("YouTube", "https://www.youtube.com/results?search_query={number}", False),
    ("Reddit", "https://www.reddit.com/search/?q={number}", False),
    ("TikTok", "https://www.tiktok.com/search/user?q={number}", False),
    ("Snapchat", "https://www.snapchat.com/add/{number}", False),
    ("Telegram", "https://t.me/{number}", True),
    ("WhatsApp", "https://wa.me/{number}", True),
    ("Signal", "https://signal.me/#p/{number}", True),
    ("Skype", "https://web.skype.com/search?search={number}", False),
    ("Discord", "https://discord.com/search?q={number}", False),
    ("Pinterest", "https://www.pinterest.com/search/pins/?q={number}", False),
    ("OnlyFans", "https://onlyfans.com/{number}", False),
    ("PayPal", "https://www.paypal.com/paypalme/{number}", False),
]

PEOPLE_SEARCH_SITES = [
    ("TruePeopleSearch", "https://www.truepeoplesearch.com/results?name={number}"),
    ("Spokeo", "https://www.spokeo.com/{number}"),
    ("Whitepages", "https://www.whitepages.com/phone/{number}"),
    ("411.com", "https://www.411.com/phone/{number}"),
    ("ZabaSearch", "https://www.zabasearch.com/people/{number}"),
    ("ThatsThem", "https://thatsthem.com/phone/{number}"),
    ("Pipl", "https://pipl.com/search/?q={number}"),
]

PHONE_COMMENT_PATTERNS = [
    ("Google posted", "https://plus.google.com/s/{number}/posts"),
    ("Pastebin", "https://pastebin.com/search?q={number}"),
    ("GitHub", "https://github.com/search?q={number}&type=code"),
]


class PhoneSocial:
    name = "phone-social"
    description = "Find social media accounts, messaging apps, and online presence linked to a phone number"

    @staticmethod
    def run(target, timeout=10):
        section(f"Phone Social Finder: {target}")

        raw_number = target.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "").replace(".", "")
        if not raw_number.startswith("+"):
            raw_number = "+" + raw_number if raw_number else raw_number
        digits_only = re.sub(r"[^\d]", "", raw_number)

        e164_format = raw_number if raw_number.startswith("+") else f"+{digits_only}"
        national_format = digits_only[-10:] if len(digits_only) >= 10 else digits_only
        results = {"messaging": [], "social_profiles": [], "people_search": [], "other": []}

        section("Phase 1: Messaging App Check")
        info(f"Checking {len(MESSAGING_APPS)} messaging platforms...")
        for app_name, url_template, desc in MESSAGING_APPS:
            try:
                url = url_template.format(number=e164_format.lstrip("+"))
                resp = requests.head(url, timeout=timeout, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200:
                    success(f"  [{app_name}] {url}")
                    results["messaging"].append({"app": app_name, "url": url, "status": resp.status_code})
                else:
                    info(f"  [{app_name}] No profile (HTTP {resp.status_code})")
            except Exception as e:
                info(f"  [{app_name}] Error: {str(e)[:50]}")

        section("Phase 2: Social Media Profile Search")
        info(f"Searhing {len(SOCIAL_SEARCH_PATTERNS)} social platforms...")
        for platform, search_url, is_direct in SOCIAL_SEARCH_PATTERNS:
            try:
                url = search_url.format(number=quote(e164_format))
                resp = requests.get(url, timeout=timeout, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if is_direct:
                        if resp.status_code == 200 and len(resp.text) > 200:
                            success(f"  [{platform}] Direct profile: {url}")
                            results["social_profiles"].append({"platform": platform, "url": url, "status": resp.status_code, "type": "direct"})
                            continue
                    else:
                        if e164_format in resp.text or national_format in resp.text or digits_only in resp.text:
                            warning(f"  [{platform}] Phone number found in search results!")
                            results["social_profiles"].append({"platform": platform, "url": url, "status": resp.status_code, "type": "mentioned"})
                        else:
                            info(f"  [{platform}] No mention found")
                else:
                    info(f"  [{platform}] HTTP {resp.status_code}")
            except Exception as e:
                info(f"  [{platform}] Error: {str(e)[:50]}")

        section("Phase 3: People Search & Reverse Phone Lookup")
        info(f"Checking {len(PEOPLE_SEARCH_SITES)} people search databases...")
        for site_name, site_url in PEOPLE_SEARCH_SITES:
            try:
                url = site_url.format(number=quote(national_format))
                resp = requests.get(url, timeout=timeout, allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                info(f"  [{site_name}] {resp.status_code} — check manually: {url[:60]}...")
                results["people_search"].append({"site": site_name, "url": url, "status": resp.status_code})
            except:
                pass

        section("Phase 4: Code Repositories & Paste Sites")
        for site_name, search_url in PHONE_COMMENT_PATTERNS:
            try:
                url = search_url.format(number=quote(e164_format))
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if e164_format in resp.text or national_format in resp.text:
                    warning(f"  [{site_name}] Phone number found in public content!")
                    results["other"].append({"site": site_name, "url": url, "found": True})
                else:
                    info(f"  [{site_name}] No mention found")
            except:
                pass

        section("Phone Social Summary")
        total_messaging = len(results["messaging"])
        total_social = len(results["social_profiles"])
        total_people = len(results["people_search"])

        result("Number", e164_format)
        result("Messaging apps found", str(total_messaging))
        result("Social profiles found", str(total_social))
        result("People search results", str(total_people))

        if total_messaging > 0:
            section("Messaging Apps")
            for m in results["messaging"]:
                success(f"  {m['app']}: {m['url']}")

        if total_social > 0:
            section("Social Media Presence")
            for s in results["social_profiles"]:
                if s["type"] == "direct":
                    success(f"  {s['platform']}: {s['url']}")
                else:
                    warning(f"  {s['platform']}: mentioned in search results")

        if total_messaging == 0 and total_social == 0:
            warning("No social media or messaging accounts found for this number")
            info("This doesn't mean they don't exist — many profiles are private or require login")

        return results
