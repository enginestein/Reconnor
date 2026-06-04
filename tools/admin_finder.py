import requests
import re
from urllib.parse import urljoin, urlparse
from utils.output import section, info, success, warning, error, result
from utils.ollama_helper import OllamaHelper

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

ADMIN_PATHS = [
    "admin", "admin/", "admin.php", "admin/index.php", "admin/login", "admin/login.php",
    "admin/panel", "admin/dashboard", "admin/controlpanel", "admin/portal", "admin/cp",
    "admin/administrator", "admin/backend", "admin/management", "admin/system",
    "administrator", "administrator/", "administrator/login.php", "administrator/index.php",
    "adminpanel", "admin-panel", "adminarea", "admin-area",
    "controlpanel", "control-panel", "cp", "cpanel", "webadmin", "sysadmin",
    "superadmin", "super-user", "backend", "management", "manage",
    "dashboard", "portal", "console", "operator",
    "login", "login.php", "login.html", "login/admin", "login/administrator",
    "signin", "sign-in", "signin.php", "signin.html",
    "auth", "auth/login", "authenticate", "authorize",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-login",
    "administrator/login", "admin/login.aspx", "login.aspx",
    "user", "user/login", "user/account", "account", "accounts",
    "my-account", "myaccount", "profile", "profiles",
    "users", "members", "member", "member/login",
    "root", "root/", "super", "super/",
    "private", "restricted", "secret", "hidden", "confidential",
    "config", "configuration", "settings", "setup", "install", "install.php",
    "dev", "development", "dev/admin", "internal", "intranet", "staff",
    "moderator", "mod", "moderator/", "mod/",
    "server-status", "server-info", "status",
    "phpmyadmin", "phpPgAdmin", "adminer", "mysqladmin",
    "pma", "myadmin", "sqladmin", "database",
    "webmail", "mail", "email", "zimbra", "roundcube", "squirrelmail",
    "cgi-bin", "cgi-bin/admin", "cgi-sys",
    "api", "api/admin", "rest", "graphql",
    "test", "tests", "testing", "demo", "demo/admin",
    "backup", "backups", "backup/admin",
]

CMS_SPECIFIC_PATHS = {
    "WordPress": ["/wp-admin/", "/wp-login.php", "/wp-admin/admin-ajax.php", "/xmlrpc.php", "/wp-content/", "/wp-json/"],
    "Joomla": ["/administrator/", "/administrator/index.php"],
    "Drupal": ["/user/login", "/user/register", "/admin", "/admin/login"],
    "Magento": ["/admin", "/index.php/admin"],
    "Shopify": ["/admin", "/admin/auth/login"],
    "PrestaShop": ["/admin/", "/admin123/", "/admin-dev/"],
    "Laravel": ["/admin", "/admin/login", "/nova/login"],
    "Symfony": ["/admin", "/admin/login"],
    "CodeIgniter": ["/admin", "/index.php/admin"],
    "Yii": ["/admin", "/index.php?r=admin"],
    "CakePHP": ["/admin", "/admin/users/login"],
    "Django": ["/admin/", "/admin/login/"],
    "Ruby on Rails": ["/admin", "/admin/login"],
    "ASP.NET": ["/admin/", "/admin/login.aspx", "/admin/default.aspx"],
    "SharePoint": ["/_layouts/15/authenticate.aspx", "/_layouts/15/settings.aspx"],
}

ADMIN_INDICATORS = [
    "admin", "login", "password", "username", "sign in", "signin",
    "dashboard", "administrator", "control panel", "cpanel", "wp-admin",
    "management", "backend", "authenticate", "authorization",
    "welcome back", "my account", "myaccount", "profile",
    "email address", "user id", "user name", "pass phrase",
    "forgot password", "reset password", "change password",
    "register", "create account", "sign up",
    "modules", "configuration", "settings", "system",
    "user management", "content management",
    "administrative", "privileges", "permissions",
    "role", "roles", "access control", "ACL",
    "session expired", "logged in", "login successful",
]


class AdvancedAdminFinder:
    name = "admin"
    description = "Advanced admin panel finder with CMS detection, fuzzy matching, login form analysis, and response fingerprinting"

    @staticmethod
    def run(target, timeout=10, threads=20, ollama_model=None):
        section(f"Advanced Admin Panel Finder: {target}")


        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        error_page_hash = None
        error_page_size = 0
        error_page_content = ""

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        try:
            resp = requests.get(f"{base_url}/nonexistent_xyz_123_test_page_abc", timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            error_page_hash = hash(resp.text[:1000])
            error_page_size = len(resp.content)
            error_page_content = resp.text
            info(f"404 baseline: status={resp.status_code}, size={error_page_size}b, hash={error_page_hash}")
        except:
            pass

        try:
            homepage_resp = requests.get(base_url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
            homepage_text = homepage_resp.text
            if HAS_BS4:
                homepage_soup = bs4.BeautifulSoup(homepage_text, "html.parser")
                detected_cms = AdvancedAdminFinder.detect_cms(homepage_soup, homepage_text)
                if detected_cms:
                    success(f"Detected CMS: {detected_cms}")
                    section(f"Testing CMS-Specific Admin Paths for {detected_cms}")
                    cms_paths = CMS_SPECIFIC_PATHS.get(detected_cms, [])
                    for cms_path in cms_paths:
                        test_url = urljoin(base_url, cms_path)
                        AdvancedAdminFinder.test_path(test_url, timeout, error_page_hash, error_page_size, error_page_content, found)
        except:
            pass

        all_paths = ADMIN_PATHS[:]
        all_paths = list(dict.fromkeys(all_paths))

        if ollama and ollama.available:
            tech_for_ollama = [detected_cms] if detected_cms else None
            section("Ollama: Generating Custom Admin Paths")
            ai_paths = ollama.generate_admin_paths(parsed.netloc, tech_for_ollama)
            if ai_paths:
                info(f"Ollama generated {len(ai_paths)} custom paths")
                for p in ai_paths:
                    if p not in all_paths:
                        all_paths.append(p)
            else:
                warning("Ollama returned no custom paths")

        section(f"Scanning {len(all_paths)} admin paths...")
        for path in all_paths:
            test_url = urljoin(base_url, path)
            AdvancedAdminFinder.test_path(test_url, timeout, error_page_hash, error_page_size, error_page_content, found)

        section("Admin Panel Results Summary")
        if found:
            success(f"Found {len(found)} potential admin panels")
            login_pages = [f for f in found if f.get("has_login_form")]
            auth_required = [f for f in found if f.get("auth_required")]
            non_404 = [f for f in found if not f.get("is_404")]

            table_headers = ["Status", "URL", "Type", "Login Form", "Auth"]
            table_rows = []
            for f in found:
                login_str = "YES" if f.get("has_login_form") else "no"
                auth_str = "YES" if f.get("auth_required") else "no"
                table_rows.append([str(f["status"]), f["url"][:50], f.get("detected_type", "page"), login_str, auth_str])
            if len(table_rows) > 5:
                table_rows = table_rows[:15]
            try:
                from utils.output import table as tbl
                tbl(table_headers, table_rows)
            except:
                pass

            if login_pages:
                section(f"Login Pages Detected ({len(login_pages)})")
                for lp in login_pages:
                    warning(f"  [{lp['status']}] {lp['url']}")
                    if lp.get("cms_type"):
                        result(f"       CMS:", lp["cms_type"])
                    if lp.get("field_count"):
                        result(f"       Fields:", str(lp["field_count"]))

            if auth_required:
                section(f"Auth-Protected Pages ({len(auth_required)})")
                for ap in auth_required[:10]:
                    result(f"  [{ap['status']}]", ap["url"])

            result("Total findings", str(len(found)))
            result("Login pages", str(len(login_pages)))
            result("Auth required", str(len(auth_required)))
        else:
            warning("No admin panels found — target may use custom paths")

        return {"target": target, "found": found}

    @staticmethod
    def test_path(test_url, timeout, error_hash, error_size, error_content, found_list):
        try:
            resp = requests.get(test_url, timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

            status = resp.status_code
            body = resp.text.lower()
            body_hash = hash(body[:1000])
            body_size = len(resp.content)

            is_404 = False
            if status in (404,):
                is_404 = True
            elif error_hash and body_hash == error_hash:
                is_404 = True
                warning(f"  Fake 404 (soft 404) for {test_url} (response matches error page)")
            elif error_size and abs(body_size - error_size) < 100 and status not in (401, 403):
                is_404 = True

            if is_404 and status in (200,):
                warning(f"  Soft 404 detected: {test_url} returns HTTP 200 but content matches error page")

            if is_404 or status in (404,):
                return

            matched_indicators = [ind for ind in ADMIN_INDICATORS if ind in body]

            has_login_form = False
            field_count = 0
            cms_type = None

            if HAS_BS4 and not is_404:
                try:
                    soup = bs4.BeautifulSoup(resp.text, "html.parser")
                    forms = soup.find_all("form")
                    for form in forms:
                        password_inputs = form.find_all("input", type="password")
                        text_inputs = form.find_all("input", type="text")
                        email_inputs = form.find_all("input", type="email")
                        submit_inputs = form.find_all("input", type="submit")
                        if password_inputs and (text_inputs or email_inputs):
                            has_login_form = True
                            field_count = len(password_inputs) + len(text_inputs) + len(email_inputs) + len(submit_inputs)
                            break

                    for cms, cms_indicators in CMS_SPECIFIC_PATHS.items():
                        for indicator in cms_indicators:
                            if indicator in test_url or indicator in resp.text[:2000].lower():
                                cms_type = cms
                                break
                except:
                    pass

            auth_required = status in (401, 403) or "authorization required" in body

            entry = {
                "url": test_url, "status": status, "size": body_size,
                "is_404": is_404, "indicators": matched_indicators[:5],
                "has_login_form": has_login_form, "field_count": field_count,
                "auth_required": auth_required, "cms_type": cms_type,
                "detected_type": "login" if has_login_form else "auth" if auth_required else "page",
            }
            found_list.append(entry)

            if has_login_form:
                success(f"[{status}] LOGIN PAGE: {test_url} (fields: {field_count})")
            elif auth_required:
                warning(f"[{status}] AUTH: {test_url}")
            elif status in (200, 201, 202, 204):
                if matched_indicators:
                    info(f"[{status}] {test_url} (indicators: {matched_indicators[:3]})")
                else:
                    info(f"[{status}] {test_url}")
            elif status in (301, 302, 303, 307, 308):
                redirect = resp.headers.get("Location", "")[:50]
                redirect_target_is_admin = any(p in redirect.lower() for p in ["admin", "login", "auth", "signin"])
                if redirect_target_is_admin:
                    warning(f"[{status}] {test_url} -> {redirect}")
                else:
                    info(f"[{status}] {test_url} -> {redirect}")
            else:
                info(f"[{status}] {test_url}")
        except Exception as e:
            pass

    @staticmethod
    def detect_cms(soup, html_text):
        cms_signatures = {
            "WordPress": [r"/wp-content/", r"/wp-includes/", r"wp-json", r'generator.*WordPress'],
            "Joomla": [r"joomla", r"/components/", r"/modules/", r'generator.*Joomla'],
            "Drupal": [r"drupal", r"/sites/default/", r"drupal.js", r'generator.*Drupal'],
            "Magento": [r"magento", r"mage/", r"Magento_", r'generator.*Magento'],
            "PrestaShop": [r"prestashop", r"/modules/", r"/themes/"],
            "Laravel": [r"laravel", r"csrf-token", r"Laravel"],
            "Shopify": [r"shopify", r"Shopify", r"myshopify"],
            "Squarespace": [r"squarespace", r"static.squarespace"],
            "Wix": [r"wix", r"wixstatic"],
            "Weebly": [r"weebly", r"weebly.com"],
            "Django": [r"csrftoken", r"django", r'Django'],
            "Ruby on Rails": [r"rails", r"csrf-param", r"authenticity_token"],
            "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp.net"],
            "SharePoint": [r"sharepoint", r"_spPageContextInfo"],
        }
        html_lower = html_text.lower()
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if re.search(sig, html_lower, re.I):
                    return cms
        return None
