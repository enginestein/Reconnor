import re
import requests
from urllib.parse import quote, urlparse, unquote
from utils.output import section, info, success, warning, error, result, table


TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
PUBLIC_TG = "https://t.me/s/{username}"
PUBLIC_TG_CHANNEL = "https://t.me/{channel}"
TG_SCRAPER = "https://t.me/s/{channel}?before={before}"


class TelegramOSINT:
    name = "telegram-osint"
    description = "Telegram OSINT: channel/group intelligence, message analysis, subscriber stats, forward tracking, profile recon"

    @staticmethod
    def run(target, timeout=15, limit=20, deep=False):
        section(f"Telegram OSINT: {target}")

        query = target.strip().lower().lstrip("@")
        results = {
            "channel_info": {}, "messages": [], "forward_sources": set(),
            "media_types": {}, "activity_timeline": [], "related_channels": [],
        }

        section("Phase 1: Channel/Profile Basic Info")
        results["channel_info"] = TelegramOSINT._get_channel_info(query, timeout)

        if results["channel_info"].get("exists"):
            section("Phase 2: Message History Analysis")
            results["messages"] = TelegramOSINT._get_messages(query, timeout, limit)

            if results["messages"]:
                section("Phase 3: Forward & Cross-Post Analysis")
                results["forward_sources"] = TelegramOSINT._analyze_forwards(results["messages"])

                section("Phase 4: Content & Media Type Analysis")
                results["media_types"] = TelegramOSINT._analyze_media(results["messages"])

                section("Phase 5: Activity Pattern Analysis")
                results["activity_timeline"] = TelegramOSINT._analyze_activity(results["messages"])

            if deep:
                section("Phase 6: Related Channels & References")
                results["related_channels"] = TelegramOSINT._find_related(query, results["messages"], timeout)

        TelegramOSINT._display_summary(query, results)
        return results

    @staticmethod
    def _get_channel_info(channel, timeout):
        info_data = {"exists": False, "title": "", "description": "", "type": "unknown",
                     "username": channel, "photo": "", "subscriber_count": None}
        try:
            url = f"https://t.me/{channel}"
            resp = requests.get(url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                info_data["exists"] = True
                text = resp.text

                title_match = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', text)
                if title_match:
                    info_data["title"] = title_match.group(1)
                    info_data["type"] = "channel" if "Channel" in text or "channel" in text or not any(s in text for s in ["group", "bot"]) else "group"
                    success(f"  Title: {info_data['title']}")
                    result("    Type", info_data["type"].title())

                desc_match = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', text)
                if desc_match:
                    info_data["description"] = desc_match.group(1)[:200]
                    result("    Description", info_data["description"][:100])

                photo_match = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', text)
                if photo_match:
                    info_data["photo"] = photo_match.group(1)
                    result("    Photo URL", f"{info_data['photo'][:60]}...")

                member_match = re.search(r'(\d[\d\s,.]*)\s*(?:member|subscriber|participant)', text, re.I)
                if member_match:
                    count_str = member_match.group(1).strip().replace(",", "").replace(" ", "").replace(".", "")
                    try:
                        info_data["subscriber_count"] = int(count_str)
                        result("    Members", f"{info_data['subscriber_count']:,}")
                    except ValueError:
                        pass

                online_match = re.search(r'(\d[\d\s,]*)\s*online', text, re.I)
                if online_match:
                    result("    Online now", online_match.group(1).strip())

            dm = re.search(r'(This channel|This group|private|private (channel|group)|bot(?!\.))',
                         text.lower()[:500])
            if dm:
                warning(f"  Channel status: {dm.group(0)}")

        except Exception as e:
            info(f"  Channel info error: {str(e)[:50]}")
        return info_data

    @staticmethod
    def _get_messages(channel, timeout, limit):
        messages = []
        try:
            url = f"https://t.me/s/{channel}"
            resp = requests.get(url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            if resp.status_code == 200:
                text = resp.text
                message_blocks = re.findall(
                    r'<div class="tgme_widget_message_wrap[^>]*>.*?</div>\s*</div>\s*</div>',
                    text, re.DOTALL
                )
                if not message_blocks:
                    message_blocks = re.findall(
                        r'<div class="tgme_widget_message[^>]*>.*?</div>\s*</div>\s*</div>',
                        text, re.DOTALL
                    )

                if not message_blocks:
                    message_blocks = re.split(r'<div class="tgme_widget_message_wrap[^>]*>', text)
                    message_blocks = [f'<div class="tgme_widget_message_wrap">' + b for b in message_blocks if b.strip()][1:]

                info(f"  Found {len(message_blocks)} message(s) on page")

                for block in message_blocks[:limit]:
                    msg = TelegramOSINT._parse_message_block(block)
                    if msg:
                        messages.append(msg)

                if not messages:
                    info("  No parseable messages found (channel may be private or empty)")
        except Exception as e:
            info(f"  Message fetch error: {str(e)[:60]}")
        return messages

    @staticmethod
    def _parse_message_block(block):
        msg = {"text": "", "date": "", "views": 0, "forwards": 0, "has_media": False,
               "media_type": "text", "forward_from": "", "message_link": ""}
        try:
            text_match = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', block, re.DOTALL)
            if text_match:
                raw = text_match.group(1)
                raw = re.sub(r'<[^>]+>', '', raw)
                raw = raw.replace('<br>', '\n').replace('<br/>', '\n').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
                msg["text"] = raw.strip()[:500]

            date_match = re.search(r'datetime=["\']([^"\']+)["\']', block)
            if date_match:
                msg["date"] = date_match.group(1)[:16]

            views_match = re.search(r'class="tgme_widget_message_views_count[^"]*"[^>]*>([^<]+)', block)
            if views_match:
                v = views_match.group(1).strip().replace(",", "").replace(" ", "")
                try:
                    msg["views"] = int(v)
                except ValueError:
                    msg["views"] = 0

            fwd_match = re.search(r'class="tgme_widget_message_forwarded_from_name[^"]*"[^>]*>([^<]+)', block)
            if fwd_match:
                msg["forward_from"] = fwd_match.group(1).strip()

            link_match = re.search(r'href=["\'](https://t\.me/[^"\']+)["\']', block)
            if link_match:
                msg["message_link"] = link_match.group(1)

            media_types = [
                (r'class="tgme_widget_message_photo', "photo"),
                (r'class="tgme_widget_message_video', "video"),
                (r'class="tgme_widget_message_document', "document"),
                (r'class="tgme_widget_message_audio', "audio"),
                (r'class="tgme_widget_message_voice', "voice"),
                (r'class="tgme_widget_message_poll', "poll"),
                (r'class="tgme_widget_message_location', "location"),
                (r'class="tgme_widget_message_link_preview', "link"),
            ]
            for pattern, mtype in media_types:
                if re.search(pattern, block):
                    msg["has_media"] = True
                    msg["media_type"] = mtype
                    break

            if not msg["text"] and not msg["has_media"]:
                return None
        except Exception:
            return None
        return msg

    @staticmethod
    def _analyze_forwards(messages):
        sources = set()
        for msg in messages:
            if msg.get("forward_from"):
                sources.add(msg["forward_from"])
        if sources:
            warning(f"  Forward sources found: {len(sources)}")
            for s in sorted(sources):
                warning(f"    Content forwarded from: @{s}")
        else:
            info("  No forwarded content detected (content appears original)")
        return sorted(sources)

    @staticmethod
    def _analyze_media(messages):
        counts = {}
        for msg in messages:
            mt = msg.get("media_type", "text")
            counts[mt] = counts.get(mt, 0) + 1
        if counts:
            media_table = [[mt, str(c), f"{c/len(messages)*100:.0f}%"] for mt, c in sorted(counts.items(), key=lambda x: -x[1])]
            table(["Type", "Count", "Pct"], media_table)
        return counts

    @staticmethod
    def _analyze_activity(messages):
        timeline = []
        dates = {}
        for msg in messages:
            if msg.get("date"):
                day = msg["date"][:10]
                dates[day] = dates.get(day, 0) + 1
        if dates:
            info(f"  Activity across {len(dates)} day(s)")
            for day, count in sorted(dates.items(), key=lambda x: -x[1])[:7]:
                info(f"    {day}: {count} messages")
                timeline.append({"date": day, "count": count})
        return timeline

    @staticmethod
    def _find_related(channel, messages, timeout):
        related = set()
        all_text = " ".join(m.get("text", "") for m in messages)
        tg_links = re.findall(r't\.me/([a-zA-Z0-9_]+)', all_text)
        for link in tg_links:
            if link.lower() != channel.lower() and len(link) > 2:
                related.add(link)
        if related:
            info(f"  Referenced channels/groups: {len(related)}")
            for r in sorted(related)[:10]:
                info(f"    @{r}")
        return sorted(related)

    @staticmethod
    def _display_summary(channel, results):
        section("Telegram OSINT Summary")
        ci = results.get("channel_info", {})
        if ci.get("exists"):
            result("Channel", channel)
            result("Title", ci.get("title", "?"))
            if ci.get("subscriber_count"):
                result("Subscribers", f"{ci['subscriber_count']:,}")
            result("Type", ci.get("type", "?").title())
            result("Messages analyzed", str(len(results.get("messages", []))))
            result("Forward sources", str(len(results.get("forward_sources", []))))
            result("Media types found", str(len(results.get("media_types", {}))))
            result("Related channels", str(len(results.get("related_channels", []))))

            msgs = results.get("messages", [])
            if msgs:
                total_views = sum(m.get("views", 0) for m in msgs)
                avg_views = total_views / len(msgs) if msgs else 0
                result("Total views", f"{total_views:,}")
                result("Avg views/post", f"{avg_views:.0f}")

                section("Recent Messages")
                for msg in msgs[:10]:
                    prefix = f"[{msg.get('date','?')}]"
                    if msg.get("has_media"):
                        prefix += f" [{msg['media_type']}]"
                    if msg.get("views"):
                        prefix += f" ({msg['views']} views)"
                    text = msg.get("text", "")[:80] if msg.get("text") else "(no text)"
                    info(f"  {prefix} {text}")
        else:
            error(f"  Channel @{channel} not found or inaccessible")
            info("  Tip: Only public Telegram channels/groups are accessible")
            info("  Try t.me/{username} in your browser to verify")

        section("OSINT Recommendations")
        if ci.get("exists"):
            info("  Enrichment:")
            info(f"    python3 main.py username {channel}")
            info(f"    python3 main.py deep-search \"{ci.get('title', channel)}\"")
            info(f"    python3 main.py pastewatch {channel}")
