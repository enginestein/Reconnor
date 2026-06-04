import re
import requests
from urllib.parse import urljoin, urlparse
from utils.output import section, info, success, warning, error, result, table

SOCIAL_PATTERNS = {
    "Facebook": [
        r"facebook\.com/[a-zA-Z0-9.]+",
        r"fb\.com/[a-zA-Z0-9.]+",
        r"m\.facebook\.com/[a-zA-Z0-9.]+",
    ],
    "Twitter/X": [
        r"twitter\.com/[a-zA-Z0-9_]+",
        r"x\.com/[a-zA-Z0-9_]+",
        r"t\.co/[a-zA-Z0-9]+",
    ],
    "Instagram": [
        r"instagram\.com/[a-zA-Z0-9_.]+",
        r"instagr\.am/[a-zA-Z0-9_.]+",
    ],
    "LinkedIn": [
        r"linkedin\.com/in/[a-zA-Z0-9_-]+",
        r"linkedin\.com/company/[a-zA-Z0-9_-]+",
        r"lnkd\.in/[a-zA-Z0-9_-]+",
    ],
    "YouTube": [
        r"youtube\.com/@[a-zA-Z0-9_-]+",
        r"youtube\.com/channel/[a-zA-Z0-9_-]+",
        r"youtube\.com/c/[a-zA-Z0-9_-]+",
        r"youtu\.be/[a-zA-Z0-9_-]+",
    ],
    "TikTok": [
        r"tiktok\.com/@[a-zA-Z0-9_.]+",
    ],
    "Reddit": [
        r"reddit\.com/user/[a-zA-Z0-9_-]+",
        r"reddit\.com/r/[a-zA-Z0-9_-]+",
    ],
    "GitHub": [
        r"github\.com/[a-zA-Z0-9_-]+",
    ],
    "GitLab": [
        r"gitlab\.com/[a-zA-Z0-9_-]+",
    ],
    "BitBucket": [
        r"bitbucket\.org/[a-zA-Z0-9_-]+",
    ],
    "Medium": [
        r"medium\.com/@[a-zA-Z0-9_-]+",
        r"medium\.com/[a-zA-Z0-9_-]+",
    ],
    "Dev.to": [
        r"dev\.to/[a-zA-Z0-9_-]+",
    ],
    "Discord": [
        r"discord\.gg/[a-zA-Z0-9]+",
        r"discord\.com/invite/[a-zA-Z0-9]+",
        r"discordapp\.com/invite/[a-zA-Z0-9]+",
    ],
    "Telegram": [
        r"t\.me/[a-zA-Z0-9_]+",
        r"telegram\.me/[a-zA-Z0-9_]+",
        r"telegram\.dog/[a-zA-Z0-9_]+",
    ],
    "WhatsApp": [
        r"wa\.me/\d+",
        r"whatsapp\.com/channel/[a-zA-Z0-9]+",
        r"chat\.whatsapp\.com/[a-zA-Z0-9]+",
    ],
    "Snapchat": [
        r"snapchat\.com/add/[a-zA-Z0-9_.]+",
    ],
    "Pinterest": [
        r"pinterest\.com/[a-zA-Z0-9_]+",
        r"pin\.it/[a-zA-Z0-9]+",
    ],
    "Twitch": [
        r"twitch\.tv/[a-zA-Z0-9_]+",
    ],
    "Spotify": [
        r"open\.spotify\.com/user/[a-zA-Z0-9]+",
        r"open\.spotify\.com/artist/[a-zA-Z0-9]+",
        r"spoti\.fi/[a-zA-Z0-9]+",
    ],
    "SoundCloud": [
        r"soundcloud\.com/[a-zA-Z0-9_-]+",
        r"snd\.sc/[a-zA-Z0-9]+",
    ],
    "Patreon": [
        r"patreon\.com/[a-zA-Z0-9_-]+",
    ],
    "Buy Me A Coffee": [
        r"buymeacoffee\.com/[a-zA-Z0-9_-]+",
        r"ko-fi\.com/[a-zA-Z0-9_-]+",
    ],
    "Etsy": [
        r"etsy\.com/shop/[a-zA-Z0-9_-]+",
    ],
    "Stack Overflow": [
        r"stackoverflow\.com/users/[0-9]+/[a-zA-Z0-9_-]+",
    ],
    "Hacker News": [
        r"news\.ycombinator\.com/user\?id=[a-zA-Z0-9_-]+",
    ],
    "Product Hunt": [
        r"producthunt\.com/@[a-zA-Z0-9_-]+",
        r"producthunt\.com/posts/[a-zA-Z0-9_-]+",
    ],
    "AngelList": [
        r"angel\.co/u/[a-zA-Z0-9_-]+",
        r"angellist\.com/[a-zA-Z0-9_-]+",
    ],
    "Crunchbase": [
        r"crunchbase\.com/person/[a-zA-Z0-9_-]+",
        r"crunchbase\.com/organization/[a-zA-Z0-9_-]+",
    ],
    "Behance": [
        r"behance\.net/[a-zA-Z0-9_-]+",
    ],
    "Dribbble": [
        r"dribbble\.com/[a-zA-Z0-9_-]+",
    ],
    "Flickr": [
        r"flickr\.com/people/[a-zA-Z0-9_-]+",
        r"flic\.kr/[a-zA-Z0-9]+",
    ],
    "Vimeo": [
        r"vimeo\.com/[a-zA-Z0-9_]+",
    ],
    "Linktree": [
        r"linktr\.ee/[a-zA-Z0-9_-]+",
    ],
    "About.me": [
        r"about\.me/[a-zA-Z0-9_-]+",
    ],
    "Keybase": [
        r"keybase\.io/[a-zA-Z0-9_-]+",
    ],
    "PayPal": [
        r"paypal\.me/[a-zA-Z0-9_-]+",
    ],
    "Venmo": [
        r"venmo\.com/[a-zA-Z0-9_-]+",
    ],
    "Cash App": [
        r"cash\.app/\$[a-zA-Z0-9_-]+",
    ],
    "Substack": [
        r"substack\.com/@[a-zA-Z0-9_-]+",
        r"[a-zA-Z0-9_-]+\.substack\.com",
    ],
    "WordPress": [
        r"[a-zA-Z0-9_-]+\.wordpress\.com",
    ],
    "Blogger": [
        r"[a-zA-Z0-9_-]+\.blogspot\.com",
    ],
}


class SocialLinker:
    name = "sociallinks"
    description = "Extract social media and contact links from a website"

    @staticmethod
    def run(target, full_scan=False):
        section(f"Social Media Link Extractor: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            resp = requests.get(
                target, timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                allow_redirects=True,
            )
            html = resp.text
        except Exception as e:
            error(f"Failed to fetch page: {e}")
            return {"target": target, "error": str(e)}

        found_links = []
        html_lower = html.lower()

        for platform, patterns in SOCIAL_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, html_lower, re.IGNORECASE)
                for match in matches:
                    if match not in [l[0] for l in found_links]:
                        url = "https://" + match
                        found_links.append((platform, url))

        if found_links:
            found_links.sort(key=lambda x: x[0])
            section(f"Found {len(found_links)} social media/contact link(s)")
            for platform, url in found_links:
                result(platform, url)
        else:
            warning("No social media links found on the page")

        platform_count = {}
        for platform, _ in found_links:
            platform_count[platform] = platform_count.get(platform, 0) + 1

        if platform_count:
            section("Platform Distribution")
            for platform, count in sorted(platform_count.items(), key=lambda x: -x[1]):
                result(platform, str(count))

        return {"target": target, "links": found_links}
