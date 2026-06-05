# Social Recon

Cross-platform social media reconnaissance. Scans 60+ social platforms for a username, extracts public metadata (OG tags, profile titles, descriptions, profile images), and correlates findings across platforms.

```
python3 main.py social-recon username
python3 main.py social-recon username --threads 150
```

**Options:**
- `--threads` — Max concurrent checks (default: 100)
- `--timeout` — HTTP timeout (default: 10)

**Platforms checked (60+):**
- **Social:** Instagram, Facebook, Twitter/X, LinkedIn, TikTok, Snapchat, Threads, Reddit, Pinterest, Mastodon, Bluesky
- **Messaging:** Telegram, Discord
- **Creative:** YouTube, Twitch, Behance, Dribbble, Flickr, DeviantArt, VSCO, Unsplash, 500px, SoundCloud, Vimeo
- **Dev/Tech:** GitHub, GitLab, StackOverflow, CodePen, Replit, NPM, PyPI, Docker, Dev.to, Medium, Kaggle, TryHackMe
- **Gaming:** Steam, Chess.com, Xbox, PlayStation
- **Audio/Video:** Spotify, SoundCloud, Vimeo
- **Business:** LinkedIn, AngelList, Crunchbase, Fiverr, Upwork
- **Crypto/Payments:** CashApp, Venmo, PayPal
- **Blogs:** WordPress, Blogger, Substack, Tumblr
- **Other:** Keybase, Gravatar, Linktree, About.me, BuyMeACoffee

**Features:**
- Profile existence detection with URL verification
- OpenGraph metadata extraction (title, description, image)
- Cross-platform name correlation
- Category-based profile grouping
- Redirect chain analysis
