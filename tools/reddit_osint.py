import re
import requests
from datetime import datetime
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table


class RedditOSINT:
    name = "reddit-osint"
    description = "Reddit OSINT: user profile analysis, subreddit recon, content tracking, cross-post detection"

    @staticmethod
    def run(target, mode="user", timeout=15, limit=25):
        section(f"Reddit OSINT: {target} [{mode}]")

        query = target.strip().lower().lstrip("/u/").lstrip("/r/").lstrip("u/").lstrip("r/")
        results = {"profile": {}, "content": [], "activity": [], "crossposts": [], "subreddits": {}}

        if mode == "user":
            section("Phase 1: User Profile")
            results["profile"] = RedditOSINT._get_user_profile(query, timeout)

            if results["profile"].get("exists"):
                section("Phase 2: Recent Posts & Comments")
                results["content"] = RedditOSINT._get_user_content(query, timeout, limit)

                if results["content"]:
                    section("Phase 3: Activity & Subreddit Analysis")
                    results["subreddits"] = RedditOSINT._analyze_subreddits(results["content"])
                    results["crossposts"] = RedditOSINT._find_crossposts(results["content"])
                    results["activity"] = RedditOSINT._analyze_activity_times(results["content"])

                section("Phase 4: Google Dork Discovery")
                RedditOSINT._dork_reddit_user(query)
            else:
                error(f"  User u/{query} not found on Reddit")

        elif mode == "subreddit":
            section("Phase 1: Subreddit Info")
            results["profile"] = RedditOSINT._get_subreddit_info(query, timeout)

            if results["profile"].get("exists"):
                section("Phase 2: Recent Top Content")
                results["content"] = RedditOSINT._get_subreddit_content(query, timeout, limit)
            else:
                error(f"  Subreddit r/{query} not found or private")

        elif mode == "search":
            section("Searching Reddit")
            results["content"] = RedditOSINT._search_reddit(query, timeout, limit)

        RedditOSINT._display_summary(query, mode, results)
        return results

    @staticmethod
    def _get_user_profile(username, timeout):
        profile = {"exists": False, "username": username, "karma": {}, "age": "",
                    "trophies": [], "description": ""}
        try:
            resp = requests.get(
                f"https://old.reddit.com/user/{username}/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if resp.status_code == 200:
                profile["exists"] = True
                text = resp.text

                if "there doesn't seem to be anything here" in text.lower() and "reddit" in text.lower():
                    page_title = re.search(r'<title>(.*?)</title>', text, re.DOTALL)
                    if page_title and "404" in page_title.group(1):
                        profile["exists"] = False
                        return profile

                link_karma = re.search(r'(\d[\d,]*)\s*link\s*karma', text, re.I)
                if link_karma:
                    profile["karma"]["link"] = link_karma.group(1)
                comment_karma = re.search(r'(\d[\d,]*)\s*comment\s*karma', text, re.I)
                if comment_karma:
                    profile["karma"]["comment"] = comment_karma.group(1)

                age_match = re.search(r'reddit\s+since\s*:?\s*([^<]+?)(?:<|\))', text, re.I)
                if age_match:
                    profile["age"] = age_match.group(1).strip()

                trophies = re.findall(r'class="trophy-name">([^<]+)', text)
                profile["trophies"] = [t.strip() for t in trophies]

                description = re.search(r'class="user-info-box"[^>]*>.*?<p>(.*?)</p>', text, re.DOTALL | re.I)
                if description:
                    profile["description"] = re.sub(r'<[^>]+>', '', description.group(1)).strip()[:200]

                success(f"  u/{username} found")
                if profile["karma"]:
                    result("  Link karma", profile["karma"].get("link", "0"))
                    result("  Comment karma", profile["karma"].get("comment", "0"))
                if profile["age"]:
                    result("  Reddit since", profile["age"])
                if profile["trophies"]:
                    result("  Trophies", ", ".join(profile["trophies"][:5]))
                if profile["description"]:
                    result("  Description", profile["description"][:100])

        except Exception as e:
            info(f"  Profile error: {str(e)[:50]}")
        return profile

    @staticmethod
    def _get_user_content(username, timeout, limit):
        content = []
        try:
            resp = requests.get(
                f"https://old.reddit.com/user/{username}/submitted/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if resp.status_code == 200:
                text = resp.text
                posts = re.findall(
                    r'<div[^>]*id=["\']thing_[^>]+>.*?<a[^>]*class=["\']title[^>]*>(.*?)</a>.*?<a[^>]*href=["\'](/[^"\']+)["\']',
                    text, re.DOTALL
                )
                entries = []
                for title, link in posts[:limit]:
                    title_clean = re.sub(r'<[^>]+>', '', title).strip()
                    subreddit_match = re.search(r'/r/([^/]+)', link)
                    sr = subreddit_match.group(1) if subreddit_match else ""
                    entries.append({
                        "title": title_clean[:200],
                        "link": link,
                        "subreddit": sr,
                        "type": "post",
                    })
                content.extend(entries)
                info(f"  Found {len(entries)} post(s)")

            comments_resp = requests.get(
                f"https://old.reddit.com/user/{username}/comments/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if comments_resp.status_code == 200:
                ctext = comments_resp.text
                comments = re.findall(
                    r'<div[^>]*class=["\']entry[^>]*>.*?<p[^>]*class=["\']parent[^>]*>.*?<a[^>]*href=["\'](/r/[^"\']+)["\'].*?</p>\s*<div[^>]*class=["\']usertext-body[^>]*>\s*<div[^>]*>\s*(.*?)</div>',
                    ctext, re.DOTALL
                )
                comment_entries = []
                for link, body in comments[:limit // 2]:
                    text_clean = re.sub(r'<[^>]+>', '', body).strip()[:200]
                    sr_match = re.search(r'/r/([^/]+)', link)
                    sr = sr_match.group(1) if sr_match else ""
                    comment_entries.append({
                        "title": text_clean[:150],
                        "link": link,
                        "subreddit": sr,
                        "type": "comment",
                    })
                content.extend(comment_entries)
                info(f"  Found {len(comment_entries)} comment(s)")
        except Exception as e:
            info(f"  Content error: {str(e)[:50]}")
        return content

    @staticmethod
    def _analyze_subreddits(content):
        sr_counts = {}
        for item in content:
            sr = item.get("subreddit", "")
            if sr:
                sr_counts[sr] = sr_counts.get(sr, 0) + 1
        if sr_counts:
            sorted_srs = sorted(sr_counts.items(), key=lambda x: -x[1])
            info(f"  Active in {len(sr_counts)} subreddit(s)")
            for sr, count in sorted_srs[:10]:
                result(f"  r/{sr}", f"{count} post(s)/comment(s)")
        return dict(sorted(sr_counts.items(), key=lambda x: -x[1])[:20])

    @staticmethod
    def _find_crossposts(content):
        crossposts = []
        for item in content:
            if "crosspost" in item.get("title", "").lower() or "cross-post" in item.get("title", "").lower():
                crossposts.append(item)
        if crossposts:
            warning(f"  Cross-post(s) detected: {len(crossposts)}")
            for cp in crossposts:
                info(f"    {cp['title'][:80]}")
        return crossposts

    @staticmethod
    def _analyze_activity_times(content):
        timeline = {}
        for item in content:
            sr = item.get("subreddit", "unknown")
            time_bucket = "unknown"
            days = 0
            timeline[sr] = timeline.get(sr, 0) + 1
        if timeline:
            sorted_tl = sorted(timeline.items(), key=lambda x: -x[1])
            for sr, count in sorted_tl[:5]:
                info(f"  r/{sr}: {count} items")
        return timeline

    @staticmethod
    def _dork_reddit_user(username):
        dorks = [
            f"site:reddit.com u/{username}",
            f"site:reddit.com user/{username}",
            f"site:old.reddit.com user/{username}",
            f'site:reddit.com "{username}"',
        ]
        info("  Google dorks for deeper discovery:")
        for d in dorks:
            info(f"    {d}")

    @staticmethod
    def _get_subreddit_info(subreddit, timeout):
        info_data = {"exists": False, "name": subreddit, "subscribers": None, "created": "",
                     "description": "", "type": "public"}
        try:
            resp = requests.get(
                f"https://old.reddit.com/r/{subreddit}/about/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if resp.status_code == 200:
                text = resp.text
                if "there doesn't seem to be anything here" in text.lower():
                    return info_data
                info_data["exists"] = True
                success(f"  r/{subreddit} found")

                subs = re.search(r'(\d[\d,]*)\s*subscribers', text, re.I)
                if subs:
                    info_data["subscribers"] = subs.group(1)
                    result("  Subscribers", info_data["subscribers"])

                created = re.search(r'created\s*:?\s*([^<]+)', text, re.I)
                if created:
                    info_data["created"] = created.group(1).strip()
                    result("  Created", info_data["created"])

                desc = re.search(r'<div[^>]*class=["\']usertext-body[^>]*>.*?<div[^>]*>(.*?)</div>', text, re.DOTALL)
                if desc:
                    info_data["description"] = re.sub(r'<[^>]+>', '', desc.group(1)).strip()[:200]
                    result("  Description", info_data["description"][:100])

                for kw in ["private", "private community", "banned", "quarantined"]:
                    if kw in text.lower():
                        warning(f"  Subreddit status: {kw}")
                        break
        except Exception as e:
            info(f"  Subreddit error: {str(e)[:50]}")
        return info_data

    @staticmethod
    def _get_subreddit_content(subreddit, timeout, limit):
        content = []
        try:
            resp = requests.get(
                f"https://old.reddit.com/r/{subreddit}/hot/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if resp.status_code == 200:
                text = resp.text
                posts = re.findall(
                    r'<a[^>]*class=["\']title[^>]*>(.*?)</a>.*?<a[^>]*href=["\'](/r/[^"\']+)["\']',
                    text, re.DOTALL
                )
                for title, link in posts[:limit]:
                    title_clean = re.sub(r'<[^>]+>', '', title).strip()
                    author_match = re.search(r'/r/' + re.escape(subreddit) + r'/comments/[^/]+/[^/]+/(?:by\s+u/)?([^/\s&"\']+)', link)
                    author = author_match.group(1) if author_match else ""
                    content.append({
                        "title": title_clean[:200],
                        "link": link[:100],
                        "author": author,
                        "subreddit": subreddit,
                        "type": "post",
                    })
                    info(f"  [{author}] {title_clean[:60]}")
        except Exception as e:
            info(f"  Subreddit content error: {str(e)[:50]}")
        return content

    @staticmethod
    def _search_reddit(query, timeout, limit):
        content = []
        try:
            resp = requests.get(
                f"https://old.reddit.com/search?q={quote(query)}&sort=relevance&t=year",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            if resp.status_code == 200:
                text = resp.text
                results_list = re.findall(
                    r'<a[^>]*class=["\']title[^>]*>(.*?)</a>.*?<a[^>]*href=["\'](/r/[^"\']+)["\']',
                    text, re.DOTALL
                )
                for title, link in results_list[:limit]:
                    title_clean = re.sub(r'<[^>]+>', '', title).strip()
                    content.append({
                        "title": title_clean[:200],
                        "link": link,
                        "type": "search_result",
                    })
                    info(f"  {title_clean[:70]}")
        except Exception as e:
            info(f"  Search error: {str(e)[:50]}")
        return content

    @staticmethod
    def _display_summary(query, mode, results):
        section("Reddit OSINT Summary")
        if mode == "user":
            profile = results.get("profile", {})
            if profile.get("exists"):
                result("Username", query)
                result("Link karma", profile.get("karma", {}).get("link", "N/A"))
                result("Comment karma", profile.get("karma", {}).get("comment", "N/A"))
                result("Reddit since", profile.get("age", "N/A"))
                result("Content analyzed", str(len(results.get("content", []))))
                result("Subreddits active in", str(len(results.get("subreddits", {}))))
                crossposts = results.get("crossposts", [])
                if crossposts:
                    result("Cross-posts found", str(len(crossposts)))

                content = results.get("content", [])
                if content:
                    section("Recent Activity")
                    for item in content[:10]:
                        prefix = f"[{item.get('subreddit', '?')}]"
                        if item.get("type") == "comment":
                            prefix += " (comment)"
                        info(f"  {prefix} {item['title'][:80]}")
                        if item.get("link"):
                            info(f"    https://old.reddit.com{item['link']}")
            else:
                error(f"  User u/{query} not accessible")

        elif mode == "subreddit":
            sr_info = results.get("profile", {})
            if sr_info.get("exists"):
                result("Subreddit", query)
                result("Subscribers", sr_info.get("subscribers", "N/A"))
                result("Created", sr_info.get("created", "N/A"))
                content = results.get("content", [])
                result("Top posts fetched", str(len(content)))
                if content:
                    section("Recent Top Posts")
                    for item in content[:10]:
                        info(f"  [{item.get('author', '?')}] {item['title'][:80]}")
            else:
                error(f"  Subreddit r/{query} not accessible")

        elif mode == "search":
            content = results.get("content", [])
            result("Search query", query)
            result("Results found", str(len(content)))

        section("OSINT Recommendations")
        if mode == "user" and results.get("profile", {}).get("exists"):
            info("  python3 main.py reddit-osint r/{top_subreddit} --mode subreddit")
            info("  python3 main.py username " + query)
            info("  python3 main.py telegram-osint @" + query)
