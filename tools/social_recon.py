import re
import requests
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.output import section, info, success, warning, error, result, table


PLATFORM_PROFILES = [
    ("Instagram", "https://www.instagram.com/{}/", "profile"),
    ("Facebook", "https://www.facebook.com/{}", "profile"),
    ("Twitter/X", "https://twitter.com/{}", "profile"),
    ("LinkedIn", "https://www.linkedin.com/in/{}", "profile"),
    ("TikTok", "https://www.tiktok.com/@{}", "profile"),
    ("Snapchat", "https://www.snapchat.com/add/{}", "profile"),
    ("YouTube", "https://www.youtube.com/@{}", "profile"),
    ("Reddit", "https://www.reddit.com/user/{}", "profile"),
    ("Pinterest", "https://www.pinterest.com/{}/", "profile"),
    ("Telegram", "https://t.me/{}", "profile"),
    ("Discord", "https://discord.com/users/{}", "profile"),
    ("Twitch", "https://www.twitch.tv/{}", "profile"),
    ("Threads", "https://www.threads.net/@{}", "profile"),
    ("GitHub", "https://github.com/{}", "profile"),
    ("Medium", "https://medium.com/@{}", "profile"),
    ("Dev.to", "https://dev.to/{}", "profile"),
    ("Behance", "https://www.behance.net/{}", "profile"),
    ("Dribbble", "https://dribbble.com/{}", "profile"),
    ("Flickr", "https://www.flickr.com/people/{}", "profile"),
    ("Vimeo", "https://vimeo.com/{}", "profile"),
    ("SoundCloud", "https://soundcloud.com/{}", "profile"),
    ("Spotify", "https://open.spotify.com/user/{}", "profile"),
    ("Patreon", "https://www.patreon.com/{}", "profile"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{}", "profile"),
    ("Keybase", "https://keybase.io/{}", "profile"),
    ("Linktree", "https://linktr.ee/{}", "profile"),
    ("About.me", "https://about.me/{}", "profile"),
    ("AngelList", "https://angel.co/u/{}", "profile"),
    ("Crunchbase", "https://www.crunchbase.com/person/{}", "profile"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}", "profile"),
    ("ProductHunt", "https://www.producthunt.com/@{}", "profile"),
    ("Wattpad", "https://www.wattpad.com/user/{}", "profile"),
    ("DeviantArt", "https://www.deviantart.com/{}", "profile"),
    ("VSCO", "https://vsco.co/{}/gallery", "profile"),
    ("Substack", "https://substack.com/@{}", "profile"),
    ("Mastodon", "https://mastodon.social/@{}", "profile"),
    ("Bluesky", "https://bsky.app/profile/{}", "profile"),
    ("Steam", "https://steamcommunity.com/id/{}", "profile"),
    ("Epic", "https://www.epicgames.com/id/{}", "profile"),
    ("Xbox", "https://www.xboxgamertag.com/search/{}", "profile"),
    ("PlayStation", "https://psnprofiles.com/{}", "profile"),
    ("Chess.com", "https://www.chess.com/member/{}", "profile"),
    ("Goodreads", "https://www.goodreads.com/{}", "profile"),
    ("Quora", "https://www.quora.com/profile/{}", "profile"),
    ("Fiverr", "https://www.fiverr.com/{}", "profile"),
    ("Upwork", "https://www.upwork.com/freelancers/~{}", "profile"),
    ("Freelancer", "https://www.freelancer.com/u/{}", "profile"),
    ("Tumblr", "https://{}.tumblr.com", "profile"),
    ("WordPress", "https://{}.wordpress.com", "profile"),
    ("Blogger", "https://{}.blogspot.com", "profile"),
    ("Gravatar", "https://en.gravatar.com/{}", "profile"),
    ("Unsplash", "https://unsplash.com/@{}", "profile"),
    ("500px", "https://500px.com/p/{}", "profile"),
    ("Kaggle", "https://www.kaggle.com/{}", "profile"),
    ("TryHackMe", "https://tryhackme.com/p/{}", "profile"),
    ("CodePen", "https://codepen.io/{}", "profile"),
    ("Replit", "https://replit.com/@{}", "profile"),
    ("StackOverflow", "https://stackoverflow.com/users/?q={}", "profile"),
    ("NPM", "https://www.npmjs.com/~{}", "profile"),
    ("PyPI", "https://pypi.org/user/{}/", "profile"),
    ("Docker", "https://hub.docker.com/u/{}", "profile"),
    ("Keybase", "https://keybase.io/{}", "profile"),
    ("CashApp", "https://cash.app/${}", "profile"),
    ("Venmo", "https://venmo.com/{}", "profile"),
    ("PayPal", "https://paypal.me/{}", "profile"),
]


class SocialRecon:
    name = "social-recon"
    description = "Cross-platform social media recon: 60+ platforms, profile discovery, metadata extraction, correlation"

    @staticmethod
    def run(target, timeout=10, threads=100):
        section(f"Social Media Reconnaissance: {target}")

        username = target.strip().lower()
        results = {"profiles": [], "metadata": {}, "correlations": []}

        section(f"Scanning {len(PLATFORM_PROFILES)} platforms for '{username}'...")

        found_profiles = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for pname, url_tmpl, check_type in PLATFORM_PROFILES:
                futures[executor.submit(
                    SocialRecon._check_platform, pname, url_tmpl, username, timeout
                )] = pname
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found_profiles.append(res)
                    success(f"[+] {res['platform']}: {res['url']}")
                    if res.get("title"):
                        result("    Title", res["title"][:60])
                    if res.get("description"):
                        result("    Desc", res["description"][:80])

        results["profiles"] = found_profiles

        section("Profile Extraction & Metadata")
        if found_profiles:
            metadata = SocialRecon._extract_metadata(found_profiles, timeout)
            results["metadata"] = metadata

            section("Cross-Platform Correlation")
            correlations = SocialRecon._correlate(found_profiles, metadata)
            results["correlations"] = correlations

        SocialRecon._display_summary(username, results)
        return results

    @staticmethod
    def _check_platform(platform, url_template, username, timeout):
        result_data = None
        try:
            if "{}" in url_template:
                url = url_template.format(username)
            else:
                url = url_template

            resp = requests.get(url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                allow_redirects=True)

            if resp.status_code != 200:
                return None

            og_title = ""
            og_desc = ""
            og_image = ""

            title_m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', resp.text)
            if title_m:
                og_title = title_m.group(1)

            desc_m = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', resp.text)
            if desc_m:
                og_desc = desc_m.group(1)

            image_m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', resp.text)
            if image_m:
                og_image = image_m.group(1)

            title_tag = re.search(r'<title>(.*?)</title>', resp.text)
            html_title = title_tag.group(1) if title_tag else ""

            platform_id = ""
            id_match = re.search(r'https://[^/]+/(?:@|user/|in/|people/|u/)?([a-zA-Z0-9_.-]+)', url)
            if id_match:
                platform_id = id_match.group(1)

            page_size = len(resp.text)
            redirect_chain = len(resp.history)

            if og_title or html_title or platform != "Facebook":
                result_data = {
                    "platform": platform,
                    "url": url,
                    "status": resp.status_code,
                    "title": og_title or html_title,
                    "description": og_desc,
                    "image": og_image,
                    "page_size": page_size,
                    "redirects": redirect_chain,
                    "platform_id": platform_id,
                }
        except Exception:
            pass
        return result_data

    @staticmethod
    def _extract_metadata(profiles, timeout):
        metadata = {}
        for p in profiles:
            platform = p["platform"]
            url = p["url"]
            metadata[platform] = {
                "title": p.get("title", ""),
                "description": p.get("description", ""),
                "image": p.get("image", ""),
                "platform_id": p.get("platform_id", ""),
                "page_size": p.get("page_size", 0),
                "redirects": p.get("redirects", 0),
            }
            if platform == "Instagram" and metadata[platform].get("title"):
                info(f"  Instagram: {metadata[platform]['title']}")
            elif platform == "Facebook" and metadata[platform].get("title"):
                info(f"  Facebook: {metadata[platform]['title']}")
            elif platform == "Twitter/X" and metadata[platform].get("title"):
                info(f"  Twitter/X: {metadata[platform]['title']}")
            elif platform == "LinkedIn" and metadata[platform].get("title"):
                info(f"  LinkedIn: {metadata[platform]['title']}")
        return metadata

    @staticmethod
    def _correlate(profiles, metadata):
        correlations = []
        titles = []
        descriptions = []
        for p in profiles:
            if p.get("title"):
                titles.append(p["title"])
            if p.get("description"):
                descriptions.append(p["description"])

        names_mentioned = {}
        for t in titles:
            words = re.findall(r'[A-Z][a-z]+', t)
            for w in words:
                if len(w) > 2:
                    names_mentioned[w] = names_mentioned.get(w, 0) + 1
        common_names = {k: v for k, v in names_mentioned.items() if v >= 2}
        if common_names:
            info(f"  Cross-platform name correlation: {common_names}")
            correlations.append({"type": "name", "matches": list(common_names.keys())})

        return correlations

    @staticmethod
    def _display_summary(username, results):
        section("Social Recon Summary")
        profiles = results.get("profiles", [])
        result("Username", username)
        result("Profiles found", str(len(profiles)))
        result("Platforms scanned", str(len(PLATFORM_PROFILES)))

        if profiles:
            section("Discovered Profiles")
            sorted_profiles = sorted(profiles, key=lambda x: x["platform"])
            for p in sorted_profiles:
                has_meta = " ✓" if p.get("title") else ""
                success(f"  {p['platform']:<12s} {p['url']}{has_meta}")

            section("Platform Categories")
            social = [p for p in sorted_profiles if p["platform"] in [
                "Instagram", "Facebook", "Twitter/X", "LinkedIn", "TikTok",
                "Snapchat", "Threads", "Mastodon", "Bluesky", "Reddit"]]
            dev = [p for p in sorted_profiles if p["platform"] in [
                "GitHub", "GitLab", "StackOverflow", "CodePen", "Replit",
                "NPM", "PyPI", "Docker", "Dev.to", "Medium"]]
            creative = [p for p in sorted_profiles if p["platform"] in [
                "Behance", "Dribbble", "Flickr", "DeviantArt", "Unsplash",
                "500px", "VSCO", "SoundCloud", "Vimeo"]]
            gaming = [p for p in sorted_profiles if p["platform"] in [
                "Steam", "Twitch", "Chess.com", "TryHackMe"]]

            categories = [
                ("Social Media", social),
                ("Developer/Technical", dev),
                ("Creative/Media", creative),
                ("Gaming", gaming),
            ]
            for cat_name, cat_profiles in categories:
                if cat_profiles:
                    info(f"  {cat_name}: {len(cat_profiles)} profile(s)")
                    for p in cat_profiles:
                        info(f"    {p['platform']}: {p['url']}")

            section("Full Profile List")
            table(
                ["Platform", "URL", "Meta"],
                [(p["platform"], p["url"][:50], "Yes" if p.get("title") else "No")
                 for p in sorted_profiles]
            )
        else:
            warning(f"  No profiles found for '{username}' on any platform")
            info("  Some platforms block automated checks; verify manually:")
            info(f"    https://www.instagram.com/{username}/")
            info(f"    https://www.facebook.com/{username}")
            info(f"    https://twitter.com/{username}")

        section("OSINT Recommendations")
        if profiles:
            platforms_str = ", ".join([p["platform"] for p in profiles[:5]])
            info(f"  Profiles active on: {platforms_str}")
            info(f"  python3 main.py reddit-osint {username}")
            info(f"  python3 main.py telegram-osint {username}")
            info(f"  python3 main.py email-recon {username}@gmail.com")
