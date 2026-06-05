# Reddit OSINT

Reddit user profile analysis, subreddit reconnaissance, and content tracking via old.reddit.com.

```
python3 main.py reddit-osint some_user
python3 main.py reddit-osint programming --mode subreddit
python3 main.py reddit-osint "search keyword" --mode search
```

**Options:**
- `--mode` — `user`, `subreddit`, or `search` (default: user)
- `--limit` — Max items to analyze (default: 25)
- `--timeout` — HTTP timeout (default: 15)

**User mode:**
- Profile info (karma, account age, trophies, description)
- Recent posts with subreddit distribution
- Recent comments
- Cross-post detection
- Activity analysis by subreddit

**Subreddit mode:**
- Subscriber count, creation date, description
- Recent top posts with authors
- Access status (public/private/quarantined)

**Search mode:**
- Searches Reddit for a keyword and returns matching posts
