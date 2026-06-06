import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.output import section, info, success, warning, error, result, table

PLATFORMS = {
    "Instagram": {"url": "https://www.instagram.com/{}/", "check": "login"},
    "Twitter/X": {"url": "https://twitter.com/{}", "check": "profile"},
    "GitHub": {"url": "https://github.com/{}", "check": "profile"},
    "Reddit": {"url": "https://reddit.com/user/{}", "check": "profile"},
    "YouTube": {"url": "https://www.youtube.com/@{}", "check": "profile"},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "check": "profile"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "check": "login"},
    "Facebook": {"url": "https://www.facebook.com/{}", "check": "login"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "check": "profile"},
    "Tumblr": {"url": "https://{}.tumblr.com/", "check": "profile"},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "check": "login"},
    "Telegram": {"url": "https://t.me/{}", "check": "profile"},
    "WhatsApp": {"url": "https://wa.me/{}", "check": "invalid"},
    "Discord": {"url": "https://discord.com/users/{}", "check": "login"},
    "Twitch": {"url": "https://www.twitch.tv/{}", "check": "profile"},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "check": "profile"},
    "Medium": {"url": "https://medium.com/@{}", "check": "profile"},
    "Dev.to": {"url": "https://dev.to/{}", "check": "profile"},
    "Hashnode": {"url": "https://hashnode.com/@{}", "check": "profile"},
    "Dribbble": {"url": "https://dribbble.com/{}", "check": "profile"},
    "Behance": {"url": "https://www.behance.net/{}", "check": "profile"},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "check": "profile"},
    "Vimeo": {"url": "https://vimeo.com/{}", "check": "profile"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "check": "profile"},
    "Bandcamp": {"url": "https://{}.bandcamp.com", "check": "profile"},
    "Keybase": {"url": "https://keybase.io/{}", "check": "profile"},
    "BitBucket": {"url": "https://bitbucket.org/{}/", "check": "profile"},
    "GitLab": {"url": "https://gitlab.com/{}", "check": "profile"},
    "Codepen": {"url": "https://codepen.io/{}", "check": "profile"},
    "Replit": {"url": "https://replit.com/@{}", "check": "profile"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/?q={}", "check": "search"},
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "check": "profile"},
    "AngelList": {"url": "https://angel.co/u/{}", "check": "profile"},
    "Crunchbase": {"url": "https://www.crunchbase.com/person/{}", "check": "profile"},
    "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "check": "profile"},
    "BuyMeACoffee": {"url": "https://www.buymeacoffee.com/{}", "check": "profile"},
    "Patreon": {"url": "https://www.patreon.com/{}", "check": "profile"},
    "Ko-fi": {"url": "https://ko-fi.com/{}", "check": "profile"},
    "Substack": {"url": "https://substack.com/@{}", "check": "profile"},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "check": "profile"},
    "Chess.com": {"url": "https://www.chess.com/member/{}", "check": "profile"},
    "Goodreads": {"url": "https://www.goodreads.com/{}", "check": "profile"},
    "MyAnimeList": {"url": "https://myanimelist.net/profile/{}", "check": "profile"},
    "Imgur": {"url": "https://imgur.com/user/{}", "check": "profile"},
    "SlideShare": {"url": "https://www.slideshare.net/{}", "check": "profile"},
    "Scribd": {"url": "https://www.scribd.com/{}", "check": "profile"},
    "Issuu": {"url": "https://issuu.com/{}", "check": "profile"},
    "About.me": {"url": "https://about.me/{}", "check": "profile"},
    "Linktree": {"url": "https://linktr.ee/{}", "check": "profile"},
    "Carrd": {"url": "https://{}.carrd.co", "check": "profile"},
    "Beacons": {"url": "https://beacons.ai/{}", "check": "profile"},
    "AllMyLinks": {"url": "https://allmylinks.com/{}", "check": "profile"},
    "TryHackMe": {"url": "https://tryhackme.com/p/{}", "check": "profile"},
    "HackTheBox": {"url": "https://app.hackthebox.com/profile/{}", "check": "login"},
    "CTFtime": {"url": "https://ctftime.org/user/{}", "check": "search"},
    "Academia": {"url": "https://independent.academia.edu/{}", "check": "profile"},
    "ResearchGate": {"url": "https://www.researchgate.net/profile/{}", "check": "profile"},
    "Google Scholar": {"url": "https://scholar.google.com/citations?user={}", "check": "search"},
    "ORCID": {"url": "https://orcid.org/{}", "check": "profile"},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "check": "profile"},
    "NPM": {"url": "https://www.npmjs.com/~{}", "check": "profile"},
    "PyPI": {"url": "https://pypi.org/user/{}/", "check": "profile"},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}", "check": "profile"},
    "RubyGems": {"url": "https://rubygems.org/profiles/{}", "check": "profile"},
    "VSCO": {"url": "https://vsco.co/{}/gallery", "check": "profile"},
    "Fiverr": {"url": "https://www.fiverr.com/{}", "check": "profile"},
    "Upwork": {"url": "https://www.upwork.com/freelancers/~{}", "check": "search"},
    "Freelancer": {"url": "https://www.freelancer.com/u/{}", "check": "profile"},
    "99designs": {"url": "https://99designs.com/profiles/{}", "check": "profile"},
    "Unsplash": {"url": "https://unsplash.com/@{}", "check": "profile"},
    "500px": {"url": "https://500px.com/p/{}", "check": "profile"},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "check": "profile"},
    "ArtStation": {"url": "https://www.artstation.com/{}", "check": "profile"},
    "Couchsurfing": {"url": "https://www.couchsurfing.com/people/{}", "check": "login"},
    "Duolingo": {"url": "https://www.duolingo.com/profile/{}", "check": "profile"},
    "Ravelry": {"url": "https://www.ravelry.com/people/{}", "check": "profile"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{}", "check": "profile"},
    "Archive.org": {"url": "https://archive.org/details/@{}", "check": "profile"},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "check": "profile"},
    "Disqus": {"url": "https://disqus.com/by/{}/", "check": "profile"},
    "HubPages": {"url": "https://hubpages.com/@{}", "check": "profile"},
    "Quora": {"url": "https://www.quora.com/profile/{}", "check": "profile"},
    "WordPress": {"url": "https://{}.wordpress.com", "check": "profile"},
    "Blogger": {"url": "https://{}.blogspot.com", "check": "profile"},
    "Weebly": {"url": "https://{}.weebly.com", "check": "profile"},
    "Wix": {"url": "https://{}.wixsite.com/site", "check": "profile"},
    "Squarespace": {"url": "https://{}.squarespace.com", "check": "profile"},
    "Jimdo": {"url": "https://{}.jimdosite.com", "check": "profile"},
    "Netlify": {"url": "https://{}.netlify.app", "check": "profile"},
    "Vercel": {"url": "https://{}.vercel.app", "check": "profile"},
    "GitHub Pages": {"url": "https://{}.github.io", "check": "profile"},
    "Surge": {"url": "https://{}.surge.sh", "check": "profile"},
    "Render": {"url": "https://{}.onrender.com", "check": "profile"},
    "Cloudflare Pages": {"url": "https://{}.pages.dev", "check": "profile"},
    "Fly.io": {"url": "https://{}.fly.dev", "check": "profile"},
    "PythonAnywhere": {"url": "https://{}.pythonanywhere.com", "check": "profile"},
    "Glitch": {"url": "https://glitch.com/@{}", "check": "profile"},
    "CodeSandbox": {"url": "https://codesandbox.io/u/{}", "check": "profile"},
    "StackBlitz": {"url": "https://stackblitz.com/@{}", "check": "profile"},
}

CHECK_TYPE_MAP = {
    "profile": lambda resp: resp.status_code == 200,
    "login": lambda resp: resp.status_code == 200 and "login" not in resp.url.lower(),
    "search": lambda resp: resp.status_code == 200,
    "invalid": lambda resp: False,
}


def check_platform(username, platform, url_template, check_type, timeout=10):
    url = url_template.format(username)
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            allow_redirects=True,
        )
        checker = CHECK_TYPE_MAP.get(check_type, CHECK_TYPE_MAP["profile"])
        if checker(resp):
            return platform, url, resp.status_code
        return None
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None


class UsernameSearch:
    name = "username"
    description = "Search for a username across 100+ social media and web platforms"

    @staticmethod
    def run(target, platforms=None, threads=50, variants=False):
        section(f"Username Search: '{target}'")

        if variants:
            usernames = list(dict.fromkeys([target, target.lower(), target.upper(), target.capitalize()]))
            info(f"Trying {len(usernames)} case variations...")
        else:
            usernames = list(dict.fromkeys([target, target.lower()]))
            info(f"Trying {len(usernames)} username(s) (original + lowercase)...")

        platform_list = list(PLATFORMS.items())
        if platforms:
            platform_filter = [p.strip().lower() for p in platforms.split(",")]
            platform_list = [(k, v) for k, v in platform_list if k.lower() in platform_filter or any(f in k.lower() for f in platform_filter)]

        all_found = {}
        total_checked = 0
        for username in usernames:
            info(f"Checking '{username}' across {len(platform_list)} platforms...")

            found = []
            checked = 0
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for pname, pconfig in platform_list:
                    futures[executor.submit(check_platform, username, pname, pconfig["url"], pconfig["check"])] = pname

                for future in as_completed(futures):
                    checked += 1
                    res = future.result()
                    if res:
                        pname, url, status = res
                        found.append((pname, url, status))
                        success(f"[+] {pname} ({username}): {url}")

            if found:
                found.sort(key=lambda x: x[0])
                print()
                success(f"Found {len(found)} profile(s) for '{username}' across {checked} platforms:")
                table(
                    ["PLATFORM", "URL", "STATUS"],
                    [(p, u, str(s)) for p, u, s in found]
                )
            else:
                warning(f"No profiles found for '{username}' across {checked} platforms")

            if found:
                all_found[username] = found
            total_checked += checked

        return {"target": target, "variants": usernames, "found": all_found, "checked": total_checked}
