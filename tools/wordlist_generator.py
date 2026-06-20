import re
import os
import requests
from urllib.parse import urlparse, urljoin
from collections import Counter
from bs4 import BeautifulSoup
from utils.output import section, info, success, warning, error, result
from utils.ollama_helper import OllamaHelper

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

COMMON_WORDS = [
    "admin", "login", "wp-admin", "wp-content", "wp-includes", "backup", "config",
    "database", "db", "sql", "test", "dev", "staging", "api", "v1", "v2",
    "graphql", "rest", "soap", "xmlrpc", "assets", "static", "uploads", "files",
    "download", "images", "css", "js", "fonts", "vendor", "node_modules",
    "src", "dist", "build", "app", "include", "lib", "core", "modules",
    "plugins", "themes", "cache", "logs", "tmp", "temp", "private", "secret",
    "debug", "info", "status", "health", "metrics", "prometheus", "swagger",
    "docs", "documentation", "readme", "changelog", "license", "robots",
    "sitemap", "crossdomain", "clientaccesspolicy", ".env", ".git", ".svn",
    ".htaccess", ".htpasswd", "phpinfo", "info.php", "shell", "cmd",
    "upload", "filemanager", "manager", "panel", "dashboard", "controlpanel",
    "cpanel", "phpmyadmin", "phpPgAdmin", "adminer", "mysql", "pma",
]

MUTATIONS = {
    "2024": "", "2025": "", "2023": "", "2026": "",
    "admin": ["adm1n", "Adm1n", "ADMIN", "Admin"],
    "password": ["p@ssword", "P@ssword", "PASSWORD", "passw0rd"],
    "backup": ["back-up", "back_up", "Backup", "BACKUP"],
    "login": ["log1n", "Log1n", "LOGIN", "Login"],
}


class WordlistGenerator:
    name = "wordlist"
    description = "Custom wordlist generator from target website content and AI patterns"

    @staticmethod
    def run(target, depth=2, out="", size="medium", min_len=3, max_len=30, mutation=False, timeout=10, ollama_model=None):
        section(f"Wordlist Generator: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None
        results = {"target": target, "wordlist": [], "total_words": 0, "output_file": None}

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        domain = parsed.netloc or parsed.hostname or ""

        info(f"Generating wordlist for {target} (size: {size})...")
        words = set()

        # 1. Extract words from domain name
        domain_parts = re.split(r'[.\-_]', domain)
        for part in domain_parts:
            if len(part) >= min_len and len(part) <= max_len:
                words.add(part.lower())

        # 2. Crawl and extract words from page content
        info("Extracting words from page content...")
        crawled_urls = set()
        to_crawl = {target}
        for _ in range(depth):
            current = to_crawl - crawled_urls
            if not current:
                break
            for url in current:
                if url in crawled_urls:
                    continue
                crawled_urls.add(url)
                try:
                    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                    if resp.status_code != 200:
                        continue

                    if HAS_BS4:
                        soup = BeautifulSoup(resp.text, "html.parser")

                        # Extract from text
                        text = soup.get_text(separator=" ", strip=True)
                        text_words = re.findall(r'[a-zA-Z][a-zA-Z0-9_\-.]{2,}', text)
                        words.update(w.lower() for w in text_words if min_len <= len(w) <= max_len)

                        # Extract from URLs/links
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            full_url = urljoin(url, href)
                            if full_url.startswith(("http://", "https://")):
                                to_crawl.add(full_url)
                            # Extract path components
                            path_parts = re.findall(r'[a-zA-Z][a-zA-Z0-9_\-.]{2,}', href)
                            words.update(p.lower() for p in path_parts if min_len <= len(p) <= max_len)

                        # Extract form field names
                        for form in soup.find_all("form"):
                            for inp in form.find_all(["input", "select", "textarea"]):
                                name = inp.get("name", "")
                                if name and min_len <= len(name) <= max_len:
                                    words.add(name.lower())
                                inp_id = inp.get("id", "")
                                if inp_id and min_len <= len(inp_id) <= max_len:
                                    words.add(inp_id.lower())

                        # Extract IDs and classes (CSS class names)
                        for tag in soup.find_all(True):
                            classes = tag.get("class", [])
                            for cls in classes:
                                if min_len <= len(cls) <= max_len:
                                    words.add(cls.lower())
                            tag_id = tag.get("id", "")
                            if tag_id and min_len <= len(tag_id) <= max_len:
                                words.add(tag_id.lower())

                        # Extract meta keywords
                        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
                        if meta_keywords and meta_keywords.get("content"):
                            for kw in meta_keywords["content"].split(","):
                                kw = kw.strip().lower()
                                if min_len <= len(kw) <= max_len:
                                    words.add(kw)

                        # Extract comments for hidden paths
                        comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
                        for comment in comments:
                            comment_words = re.findall(r'[a-zA-Z][a-zA-Z0-9_\-.]{2,}', comment)
                            words.update(w.lower() for w in comment_words if min_len <= len(w) <= max_len)

                        # Extract from script src values
                        for script in soup.find_all("script", src=True):
                            src = script["src"]
                            parts = re.findall(r'[a-zA-Z][a-zA-Z0-9_\-.]{2,}', src)
                            words.update(p.lower() for p in parts if min_len <= len(p) <= max_len)

                except Exception as e:
                    pass

        # 3. Add common words based on size
        size_maps = {"small": 200, "medium": 500, "large": 1000}
        num_common = size_maps.get(size, 500)
        for word in COMMON_WORDS[:num_common]:
            if min_len <= len(word) <= max_len:
                words.add(word)

        # 4. Apply mutations if enabled
        if mutation:
            info("Applying mutations...")
            new_words = set()
            for word in words:
                for original, variants in MUTATIONS.items():
                    if original in word.lower():
                        for variant in variants:
                            mutated = word.lower().replace(original, variant)
                            if min_len <= len(mutated) <= max_len:
                                new_words.add(mutated)

                # Leetspeak: a->4, e->3, i->1, o->0, s->5
                leet = word.lower().replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "5")
                if leet != word.lower() and min_len <= len(leet) <= max_len:
                    new_words.add(leet)

                # Capitalized
                cap = word.capitalize()
                if cap != word and min_len <= len(cap) <= max_len:
                    new_words.add(cap)

                # Uppercase
                upper = word.upper()
                if upper != word and min_len <= len(upper) <= max_len:
                    new_words.add(upper)

            words.update(new_words)
            info(f"Generated {len(new_words)} mutated words")

        # 5. AI-generated words
        if ollama and ollama.available:
            info("Ollama: generating AI-suggested wordlist entries...")
            # Get first 2000 chars of page content for AI context
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0"})
                page_snippet = resp.text[:3000]
            except:
                page_snippet = ""

            ai_words = ollama.generate_wordlist_entries(target, domain, page_snippet)
            if ai_words:
                for w in ai_words:
                    w = w.strip().lower().strip("/").strip(".")
                    if min_len <= len(w) <= max_len and w not in words:
                        words.add(w)
                info(f"AI contributed {len(ai_words)} words")

        # 6. Sort and deduplicate
        sorted_words = sorted(words)

        # 7. Write output
        if out:
            filepath = out
        else:
            safe_domain = domain.replace(":", "_").replace("/", "_")
            filepath = f"wordlist_{safe_domain}_{size}.txt"

        with open(filepath, "w") as f:
            for word in sorted_words:
                f.write(word + "\n")

        file_size = os.path.getsize(filepath)
        success(f"Wordlist saved: {filepath} ({len(sorted_words)} words, {file_size / 1024:.1f} KB)")
        result("Total Words", str(len(sorted_words)))
        result("Output", filepath)
        result("Size", size)
        result("Mutation", str(mutation))

        # Show sample
        info(f"Sample: {', '.join(sorted_words[:20])}")

        results["wordlist"] = sorted_words
        results["total_words"] = len(sorted_words)
        results["output_file"] = filepath
        return results
