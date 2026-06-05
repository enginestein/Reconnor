# Telegram OSINT

Telegram channel/group intelligence: profile info, message analysis, forward tracking, media type analysis, activity patterns, and related channel discovery.

```
python3 main.py telegram-osint @channel_name
python3 main.py telegram-osint channel_name --deep
python3 main.py telegram-osint username --limit 50
```

**Options:**
- `--limit` — Max messages to analyze (default: 20)
- `--timeout` — HTTP timeout (default: 15)
- `--deep`, `-d` — Deep scan with related channel discovery

**Extracts:**
- Channel title, description, type (channel/group/bot)
- Subscriber count and online status
- Message content, dates, view counts
- Forwarded-from sources (content origin tracking)
- Media type distribution (photo, video, document, audio, poll, link)
- Activity timeline (posting frequency by day)
- Related channels mentioned in messages
