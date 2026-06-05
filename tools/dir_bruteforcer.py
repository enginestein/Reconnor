import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from utils.output import section, info, success, warning, error, table
from utils.ollama_helper import OllamaHelper
from utils.external_tools import ffuf_dir_bust, gobuster_dir_bust, find_tool

COMMON_PATHS = [
    "admin", "login", "wp-admin", "administrator", "backup", "backups",
    "config", "configuration", "conf", "db", "database", "sql", "dump",
    "admin.php", "login.php", "index.php", "config.php", "setup.php",
    "install.php", "wp-login.php", "phpmyadmin", "phpmyadmin/",
    "pma", "myadmin", "adminer.php", "admin/", "admin/index.php",
    "css", "js", "img", "images", "assets", "static", "uploads",
    "files", "download", "downloads", "backup.sql", "dump.sql",
    ".git/", ".git/config", ".git/HEAD", ".env", ".env.example",
    ".htaccess", ".htpasswd", "sitemap.xml", "robots.txt",
    "crossdomain.xml", "clientaccesspolicy.xml", "README.md",
    "CHANGELOG", "LICENSE", "composer.json", "package.json",
    "web.config", "Dockerfile", "docker-compose.yml",
    "api", "api/", "api/v1", "api/v2", "rest", "graphql",
    "swagger.json", "swagger.yaml", "openapi.json",
    "server-status", "server-info", "sites/default/settings.php",
    "wp-content/", "wp-includes/", "wp-json/",
    "xmlrpc.php", "wp-cron.php", "wp-admin/admin-ajax.php",
    "test", "tests", "testing", "dev", "development", "staging",
    "tmp", "temp", "log", "logs", "error.log", "access.log",
    "debug", "info.php", "phpinfo.php", "test.php",
    "shell", "cmd", "exec", "console", "terminal",
    "proxy", "proxy.php", "cgi-bin/", "cgi-bin/test.cgi",
    "vendor/", "node_modules/", "bower_components/",
    "index.html", "index.htm", "default.aspx", "default.asp",
    "README", "TODO", "CHANGELOG.md", "CONTRIBUTING.md",
    "dashboard", "panel", "cpanel", "whm", "webmail",
    "status", "health", "healthcheck", "healthz",
    "metrics", "prometheus", "grafana", "kibana",
    "actuator", "actuator/health", "actuator/info",
    "index.php", "index.html", "index.htm", "default.aspx", "default.asp",
    "home", "home.php", "main", "main.php", "about", "about.php",
    "contact", "contact.php", "contact-us", "services", "products",
    "product", "category", "categories", "item", "items",
    "search", "search.php", "results", "result", "page", "pages",
    "news", "news.php", "blog", "blog.php", "article", "articles",
    "gallery", "gallery.php", "portfolio", "events", "event",
    "faq", "faq.php", "help", "help.php", "support",
    "terms", "privacy", "privacy-policy", "disclaimer",
    "sitemap", "sitemap.xml", "sitemap.php", "sitemap_index.xml",
    "feed", "rss", "rss.xml", "atom.xml", "feed.xml",
    "comments", "comments.php", "trackback",
    "error", "error.php", "404", "404.php", "500",
    "page-not-found", "not-found", "maintenance", "coming-soon",
    "offline", "under-construction", "construction",
    "stats", "statistics", "analytics", "counter",
    "advertising", "ads", "ads.txt",
    "email", "mail", "newsletter", "subscribe", "unsubscribe",
    "survey", "poll", "polls", "vote", "voting",
    "forum", "forums", "board", "boards", "thread", "threads",
    "member", "members", "profile", "profiles", "user", "users",
    "account", "accounts", "settings", "preferences", "options",
    "my-account", "myaccount", "dashboard",
    "register", "registration", "signup", "sign-up",
    "password", "forgot-password", "reset-password", "change-password",
    "oauth", "oauth2", "authorize", "callback", "redirect",
    "token", "tokens", "refresh-token", "access-token",
    "logout", "log-out", "signout", "sign-out",
    "cart", "shopping-cart", "checkout", "wishlist",
    "order", "orders", "order-history", "invoice", "invoices",
    "payment", "payments", "billing", "receipt",
    "shipping", "delivery", "track", "tracking",
    "shop", "store", "products", "product-category",
    "item", "items", "catalog", "catalogue", "inventory",
    "review", "reviews", "rating", "ratings",
    "download", "downloads", "file", "files",
    "upload", "uploads", "media", "multimedia",
    "image", "images", "img", "photo", "photos", "picture", "pictures",
    "video", "videos", "audio", "music", "sound",
    "doc", "docs", "documents", "documentation",
    "pdf", "csv", "xml", "json", "xls", "xlsx", "zip", "tar", "gz",
    "software", "apps", "app", "application", "applications",
    "plugin", "plugins", "addon", "addons", "extension", "extensions",
    "module", "modules", "component", "components", "widget", "widgets",
    "theme", "themes", "template", "templates", "layout", "layouts",
    "style", "styles", "stylesheet", "css", "scss", "sass", "less",
    "script", "scripts", "js", "javascript",
    "font", "fonts", "icon", "icons",
    "api", "rest", "rest-api", "graphql", "v1", "v2", "v3",
    "auth", "login", "signin", "sign-in", "log-in",
    "endpoint", "endpoints", "webhook", "webhooks",
    "callback", "callbacks", "hook", "hooks",
    "integration", "integrations", "connect", "connector",
    "cron", "cronjob", "task", "tasks", "job", "jobs",
    "queue", "queues", "worker", "workers",
    "notification", "notifications", "push",
    "sms", "email", "mailer", "mailgun", "sendgrid",
    "sms", "twilio", "nexmo", "vonage",
    "chat", "livechat", "live-support", "support-chat",
    "helpdesk", "ticket", "tickets",
    "geo", "location", "locations", "map", "maps",
    "search", "search-engine", "crawl", "crawler",
    "proxy", "proxy-list", "mirror", "mirrors",
    "cache", "cached", "speedtest",
    "test", "tests", "testing", "sandbox", "playground",
    "demo", "demo1", "demo2", "sample", "samples",
    "example", "examples", "tutorial", "tutorials",
    "howto", "how-to", "guide", "guides",
    "reference", "ref", "manual", "manuals",
    "faq", "faqs", "help", "help-center",
    "knowledgebase", "knowledge-base", "kb",
    "forum", "forums", "community", "group", "groups",
    "social", "facebook", "twitter", "instagram", "linkedin",
    "blog", "blogs", "weblog", "journal", "news",
    "press", "press-release", "press-releases",
    "media", "media-center", "newsroom",
    "about-us", "about-us", "team", "our-team",
    "company", "careers", "career", "jobs", "job",
    "partners", "partner", "affiliates", "affiliate",
    "investors", "investor", "investor-relations",
    "contact-us", "contact", "get-in-touch",
    "feedback", "suggestions", "complaints",
    "legal", "privacy", "privacy-policy", "terms", "terms-of-service",
    "cookie-policy", "cookies", "gdpr", "ccpa",
    "accessibility", "accessibility-statement",
    "security", "security-policy", "responsible-disclosure",
    "bug-bounty", "hall-of-fame", "security.txt",
    "license", "licenses", "copyright", "trademark",
    "disclaimer", "impressum", "imprint",
    "page/1", "page/2", "page/3",
    "?page=1", "?page=2",
    "tag", "tags", "label", "labels",
    "category", "categories", "archive", "archives",
    "author", "authors", "writer", "writers",
    "date", "dates", "2020", "2021", "2022", "2023", "2024",
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
    "11", "12", "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
    "en", "fr", "de", "es", "it", "pt", "ru", "ja", "zh", "ko",
    "ar", "hi", "bn", "pa", "ta", "te", "mr", "gu", "kn", "ml",
    "english", "french", "german", "spanish", "italian",
    "portuguese", "russian", "japanese", "chinese", "korean",
    "lang", "language", "languages",
    "country", "countries", "region", "regions",
    "state", "states", "city", "cities",
    "us", "uk", "ca", "au", "nz", "in", "de", "fr", "jp", "cn",
    "europe", "asia", "africa", "americas", "oceania",
    "world", "global", "international",
    "section", "sections", "part", "parts",
    "chapter", "chapters", "volume", "volumes",
    "type", "types", "kind", "kinds", "sort", "sorts",
    "format", "formats", "mode", "modes",
    "list", "lists", "grid", "table", "tables",
    "detail", "details", "summary", "brief",
    "preview", "previews", "thumbnail", "thumbnails",
    "full", "fullscreen", "popup", "overlay",
    "print", "printable", "pdf", "export",
    "share", "social-share", "embed",
    "bookmark", "bookmarks", "favorite", "favorites",
    "like", "likes", "dislike", "dislikes",
    "rate", "rating", "ratings", "star", "stars",
    "top", "best", "popular", "trending", "featured",
    "new", "latest", "recent", "updated",
    "random", "related", "similar",
    "calendar", "schedule", "timetable",
    "live", "stream", "streaming", "broadcast",
    "upcoming", "past", "previous", "next",
    "first", "last", "previous", "next",
    "beginner", "intermediate", "advanced", "expert",
    "basic", "standard", "premium", "pro", "enterprise",
    "free", "paid", "trial", "demo",
    "small", "medium", "large", "extra-large",
    "mini", "micro", "nano", "pico",
]

EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".do", ".html", ".htm", ".txt", ".bak", ".old", ".swp"]


def check_path(base_url, path, timeout=10):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403, 500]:
            size = len(resp.content)
            return path, resp.status_code, size, url
    except requests.exceptions.RequestException:
        pass
    return None


class DirBruteforcer:
    name = "dir-bust"
    description = "Brute force directories and files on a web server"

    @staticmethod
    def run(target, wordlist=None, extensions=False, threads=30, timeout=10, ollama_model=None, ext=False):
        section(f"Directory Brute Forcing: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        found = []
        ext_used = set()

        if ext:
            section("External Directory Tools")
            ext_wordlist = wordlist
            if not ext_wordlist:
                warning("Use --wordlist <file> with --ext for external tools to be effective")

            if ext_wordlist:
                ffuf_results = ffuf_dir_bust(target, ext_wordlist)
                if ffuf_results:
                    for code, path, size, url in ffuf_results:
                        found.append((code, path, size, url))
                        ext_used.add(path)
                    success(f"ffuf found {len(ffuf_results)} paths")

                gobuster_results = gobuster_dir_bust(target, ext_wordlist)
                if gobuster_results:
                    for code, path, size, url in gobuster_results:
                        if path not in ext_used:
                            found.append((code, path, size, url))
                            ext_used.add(path)
                    success(f"gobuster found {len(gobuster_results)} paths")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        paths = COMMON_PATHS.copy()
        if ollama and ollama.available:
            section("Ollama: Generating Custom Directory Paths")
            try:
                tech_resp = requests.get(target, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                tech_hint = None
                from urllib.parse import urlparse
                domain = urlparse(target).netloc
                server_hint = tech_resp.headers.get("Server", "")
                powered_by = tech_resp.headers.get("X-Powered-By", "")
                tech_hint = [s for s in [server_hint, powered_by] if s]
                ai_paths = ollama.generate_dir_paths(domain, tech_hint)
                if ai_paths:
                    info(f"Ollama generated {len(ai_paths)} custom paths")
                    for p in ai_paths:
                        clean = p.lstrip("/")
                        if clean and clean not in paths:
                            paths.append(clean)
            except Exception as e:
                warning(f"Ollama path generation skipped: {e}")

        if wordlist:
            try:
                with open(wordlist) as f:
                    extra = [line.strip() for line in f if line.strip()]
                    paths.extend(extra)
                info(f"Loaded {len(extra)} paths from {wordlist}")
            except FileNotFoundError:
                error(f"Wordlist not found: {wordlist}")

        if extensions:
            expanded = []
            for p in paths:
                if "." not in p.split("/")[-1]:
                    for ext in EXTENSIONS:
                        expanded.append(p + ext)
                else:
                    expanded.append(p)
            paths = list(set(expanded))

        info(f"Checking {len(paths)} paths on {target}...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, target, p, timeout): p for p in paths}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    path, code, size, url = res
                    if path not in ext_used:
                        found.append((code, path, size, url))
                    code_str = str(code)
                    if code in [200, 201, 204]:
                        success(f"[{code}] {path} ({size} bytes)")
                    elif code in [301, 302, 307, 308]:
                        info(f"[{code}] {path}")
                    elif code in [401, 403]:
                        warning(f"[{code}] {path}")
                    else:
                        info(f"[{code}] {path}")

        found.sort(key=lambda x: x[1])
        if found:
            success(f"Found {len(found)} accessible path(s):")
        else:
            warning("No accessible paths discovered")

        return {"target": target, "paths": found}
