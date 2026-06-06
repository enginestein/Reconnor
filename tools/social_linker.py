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
        r"t\.me/\+[a-zA-Z0-9_-]+",
        r"telegram\.me/[a-zA-Z0-9_]+",
        r"telegram\.me/joinchat/[a-zA-Z0-9_-]+",
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
    "Mastodon": [
        r"[a-zA-Z0-9.-]+\.mastodon\.\w+/@[a-zA-Z0-9_]+",
        r"mastodon\.social/@[a-zA-Z0-9_]+",
        r"mastodon\.online/@[a-zA-Z0-9_]+",
        r"mastodon\.cloud/@[a-zA-Z0-9_]+",
    ],
    "Bluesky": [
        r"bsky\.app/profile/[a-zA-Z0-9_.-]+",
    ],
    "Threads": [
        r"threads\.net/@[a-zA-Z0-9_.-]+",
    ],
    "WeChat": [
        r"weixin\.qq\.com",
        r"wechat\.com",
    ],
    "Signal": [
        r"signal\.me/[a-zA-Z0-9]+",
        r"signal\.team/[a-zA-Z0-9]+",
    ],
    "Element/Matrix": [
        r"matrix\.to/#/@[a-zA-Z0-9_.-]+:[a-zA-Z0-9.-]+",
        r"element\.io",
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

        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
        email_links = [e for e in emails if not e.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js'))]

        phone_patterns = [
            r'\+\d{1,3}[-\s]?\(?\d{1,4}\)?[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{1,4}',
            r'0\d[-\s]?\d{4}[-\s]?\d{4}',
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        ]
        phones = set()
        for pp in phone_patterns:
            for m in re.findall(pp, html):
                phones.add(m.strip())

        if found_links:
            found_links.sort(key=lambda x: x[0])
            section(f"Found {len(found_links)} social media/contact link(s)")
            for platform, url in found_links:
                result(platform, url)
        else:
            warning("No social media links found on the page")

        if full_scan and found_links:
            section("Link Health Check")
            for platform, url in found_links[:20]:
                try:
                    hr = requests.head(url, timeout=5, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"})
                    status = hr.status_code
                    if status < 400:
                        success(f"  {platform}: {url} -> HTTP {status}")
                    else:
                        warning(f"  {platform}: {url} -> HTTP {status}")
                except Exception:
                    error(f"  {platform}: {url} -> UNREACHABLE")

        title = ""
        og_title = ""
        og_desc = ""
        m_title = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m_title:
            title = m_title.group(1).strip()
        m_og_title = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m_og_title:
            og_title = m_og_title.group(1).strip()
        m_og_desc = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m_og_desc:
            og_desc = m_og_desc.group(1).strip()

        section("Page Metadata")
        result("Title", title[:100] if title else "N/A")
        result("OG Title", og_title[:100] if og_title else "N/A")
        result("OG Description", og_desc[:200] if og_desc else "N/A")

        if email_links:
            section(f"Emails Found ({len(email_links)})")
            for e in list(email_links)[:20]:
                result("Email", e)
        else:
            info("No emails found")

        if phones:
            section(f"Phone Numbers Found ({len(phones)})")
            for p in list(phones)[:10]:
                result("Phone", p)
        else:
            info("No phone numbers found")

        platform_count = {}
        for platform, _ in found_links:
            platform_count[platform] = platform_count.get(platform, 0) + 1

        if platform_count:
            section("Platform Distribution")
            for platform, count in sorted(platform_count.items(), key=lambda x: -x[1]):
                result(platform, str(count))

        return {
            "target": target,
            "links": found_links,
            "emails": list(email_links),
            "phones": list(phones),
            "title": title,
            "og_title": og_title,
            "og_description": og_desc,
        }
