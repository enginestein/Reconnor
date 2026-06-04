import re
import requests
import hashlib
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table

HIBP_API = "https://api.pwnedpasswords.com/range/"
SOCIAL_PLATFORMS = [
    ("GitHub", "https://github.com/{username}"),
    ("Twitter/X", "https://twitter.com/{username}"),
    ("Instagram", "https://instagram.com/{username}"),
    ("LinkedIn", "https://linkedin.com/in/{username}"),
    ("Reddit", "https://reddit.com/user/{username}"),
    ("YouTube", "https://youtube.com/@{username}"),
    ("TikTok", "https://tiktok.com/@{username}"),
    ("Pinterest", "https://pinterest.com/{username}"),
    ("Medium", "https://medium.com/@{username}"),
    ("Dev.to", "https://dev.to/{username}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={username}"),
    ("Keybase", "https://keybase.io/{username}"),
    ("Flickr", "https://flickr.com/people/{username}"),
    ("BitBucket", "https://bitbucket.org/{username}"),
    ("GitLab", "https://gitlab.com/{username}"),
    ("AngelList", "https://angel.co/u/{username}"),
    ("ProductHunt", "https://producthunt.com/@{username}"),
    ("Replit", "https://replit.com/@{username}"),
    ("Codepen", "https://codepen.io/{username}"),
    ("Gravatar", "https://gravatar.com/{username}"),
]

EMAIL_SEARCH_URLS = [
    ("Google", "https://www.google.com/search?q={email}"),
    ("Bing", "https://www.bing.com/search?q={email}"),
    ("Yahoo", "https://search.yahoo.com/search?p={email}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={email}"),
    ("Yandex", "https://yandex.com/search/?text={email}"),
    ("Baidu", "https://www.baidu.com/s?wd={email}"),
]

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


class EmailRecon:
    name = "email-recon"
    description = "Full email intelligence: breach checks, social media discovery, username extraction, search engine footprint, reputation analysis"

    @staticmethod
    def run(target, timeout=10):
        section(f"Email Reconnaissance: {target}")

        email = target.strip().lower()
        if not EMAIL_REGEX.match(email):
            error(f"Invalid email format: {email}")
            return {"target": email, "error": "Invalid email format"}

        username = email.split("@")[0]
        domain = email.split("@")[1]
        results = {"breach": [], "social": [], "search": [], "gravatar": None, "username_info": {}}

        section(f"Phase 1: Email Structure Analysis")
        info(f"Email: {email}")
        info(f"Username: {username}")
        result("Domain", domain)
        result("Username pattern", EmailRecon.analyze_username_pattern(username))
        result("TLD", domain.split(".")[-1])
        result("Domain type", "Personal (gmail/yahoo/outlook)" if domain in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com", "mail.com", "icloud.com", "zoho.com", "yandex.com", "gmx.com") else "Custom domain")

        section("Phase 2: Breach Database Check (HIBP)")
        sha1_hash = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            resp = requests.get(f"{HIBP_API}{prefix}", timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                hashes = resp.text.split("\r\n")
                matched = [h for h in hashes if h.startswith(suffix)]
                if matched:
                    count = int(matched[0].split(":")[1])
                    warning(f"Email found in {count} breach(es) via HIBP!")
                    results["breach"].append({"source": "HIBP", "count": count, "message": f"Pwned in {count} breach(es)"})
                else:
                    success("No breaches found in HIBP database (good)")
            elif resp.status_code == 429:
                warning("HIBP rate limited — try again later")
            else:
                info(f"HIBP returned HTTP {resp.status_code}")
        except Exception as e:
            info(f"HIBP check failed: {e}")

        section("Phase 3: Social Media Account Discovery")
        info(f"Searching {len(SOCIAL_PLATFORMS)} platforms for username '{username}'...")
        found_platforms = 0
        for platform, url_template in SOCIAL_PLATFORMS:
            url = url_template.format(username=quote(username))
            try:
                resp = requests.head(url, timeout=timeout, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200:
                    success(f"  [{platform}] {url}")
                    results["social"].append({"platform": platform, "url": url, "status": resp.status_code})
                    found_platforms += 1
                else:
                    info(f"  [{platform}] Not found (HTTP {resp.status_code})")
            except:
                pass

        if found_platforms == 0:
            info("  No social media accounts found for this exact username")

        section("Phase 4: Search Engine Footprint")
        info(f"Checking {len(EMAIL_SEARCH_URLS)} search engines for email mentions...")
        for engine_name, search_url in EMAIL_SEARCH_URLS:
            url = search_url.format(email=quote(email))
            try:
                resp = requests.get(url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if email in resp.text.lower():
                    warning(f"  [{engine_name}] Email found in search results!")
                    results["search"].append({"engine": engine_name, "found": True})
                else:
                    info(f"  [{engine_name}] No direct email mention found")
            except:
                pass

        section("Phase 5: Gravatar Profile Check")
        md5_hash = hashlib.md5(email.encode()).hexdigest().lower()
        gravatar_url = f"https://gravatar.com/{md5_hash}.json"
        try:
            resp = requests.get(gravatar_url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                profile = resp.json()
                entry = profile.get("entry", [{}])[0]
                display_name = entry.get("displayName", "Unknown")
                thumb_url = entry.get("thumbnailUrl", "")
                success(f"Gravatar profile found: {display_name}")
                result("  Display Name", display_name)
                result("  Avatar", thumb_url[:80] if thumb_url else "none")
                results["gravatar"] = {"display_name": display_name, "thumbnail_url": thumb_url}
                if entry.get("urls"):
                    for u in entry["urls"]:
                        info(f"  Linked account: {u.get('value','')}")
            else:
                info("No Gravatar profile found")
        except:
            info("Gravatar check failed")

        section("Phase 6: Username Pattern Analysis")
        pattern_info = EmailRecon.analyze_username(username)
        results["username_info"] = pattern_info
        for key, val in pattern_info.items():
            if val:
                result(f"  {key.replace('_', ' ').title()}", str(val))

        section("Email Reconnaissance Summary")
        total_breaches = len(results["breach"])
        total_social = len(results["social"])
        total_search = len(results["search"])

        result("Email", email)
        result("Username", username)
        result("Domain", domain)
        result("Breaches found", str(total_breaches))
        result("Social accounts", str(total_social))
        result("Search engine mentions", str(total_search))
        result("Gravatar profile", "Yes" if results["gravatar"] else "No")

        if total_breaches:
            error(f"WARNING: Email has been compromised in data breaches!")
        if total_social:
            warning(f"Username '{username}' found on {total_social} social platform(s)")
        else:
            info("No social media accounts found for this username")

        return results

    @staticmethod
    def analyze_username(username):
        info = {}
        info["length"] = len(username)
        info["has_dots"] = "." in username
        info["has_underscores"] = "_" in username
        info["has_numbers"] = bool(re.search(r"\d", username))
        info["has_hyphens"] = "-" in username
        info["is_all_lower"] = username.islower()
        info["is_all_upper"] = username.isupper()
        info["has_mixed_case"] = any(c.isupper() for c in username) and any(c.islower() for c in username)
        birth_year_match = re.search(r"(19[0-9]{2}|20[0-9]{2})", username)
        info["birth_year"] = birth_year_match.group(1) if birth_year_match else None
        info["common_first_name"] = EmailRecon.is_common_name(username.lower().split(".")[0] if "." in username else username)
        return info

    @staticmethod
    def analyze_username_pattern(username):
        if "." in username:
            parts = username.split(".")
            if len(parts) == 2:
                return "first.last"
            return "multi-part"
        elif "_" in username:
            return "first_last"
        elif re.match(r"^[a-z]+\d+$", username):
            return "word+numbers"
        elif re.match(r"^[a-z]+$", username):
            return "single_word"
        elif re.match(r"^[a-z][a-z0-9]+$", username):
            return "alphanumeric"
        return "custom"

    @staticmethod
    def is_common_name(name):
        common = ["john", "jane", "mike", "sarah", "david", "emma", "james", "olivia",
                  "robert", "ava", "william", "sophia", "richard", "mia", "joseph",
                  "charlotte", "thomas", "amelia", "chris", "alex", "sam", "daniel",
                  "matthew", "andrew", "joshua", "ryan", "nick", "peter", "steve",
                  "mark", "paul", "george", "tom", "jack", "harry", "oliver", "charlie"]
        return name.lower() in common
