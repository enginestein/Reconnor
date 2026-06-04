from utils.output import section, info, success, warning, error, result, table

DORKS = {
    "Login Pages": [
        'inurl:login',
        'inurl:admin/login',
        'inurl:wp-login',
        'intitle:"login" "admin"',
        'inurl:user/login',
    ],
    "Configuration Files": [
        'filetype:env DB_PASSWORD',
        'filetype:xml config',
        'filetype:conf "httpd"',
        'filetype:cnf "my.cnf"',
        'filetype:sql "INSERT INTO" password',
    ],
    "Exposed Documents": [
        'filetype:pdf "confidential"',
        'filetype:xls "password"',
        'filetype:docx "internal use"',
        'filetype:csv "credit card"',
        '"strictly confidential" filetype:pdf',
    ],
    "Code Repositories": [
        'intitle:"index of" .git',
        'intitle:"index of" ".svn"',
        'intitle:"index of" "backup"',
        'intitle:"index of" "src"',
        'intitle:"index of" "node_modules"',
    ],
    "Database Exposure": [
        'inurl:phpmyadmin/index.php',
        'inurl:adminer.php',
        'intitle:"phpMyAdmin" "Welcome to"',
        'inurl:sql.php',
        'intitle:"MySQL Error" "Warning"',
    ],
    "Camera Streams": [
        'inurl:"view/view.shtml"',
        'intitle:"Live View / - AXIS"',
        'intitle:"webcamXP"',
        'inurl:"webcam" intitle:"snapshot"',
    ],
    "Cloud Storage": [
        'site:s3.amazonaws.com "backup"',
        'site:blob.core.windows.net "config"',
        'site:drive.google.com "confidential"',
        'site:pastebin.com "password" "gmail"',
    ],
    "Error Messages": [
        'intitle:"Warning" "mysql_connect()"',
        '"Fatal error:" "include_once"',
        '"Warning: preg_replace()"',
        '"Notice: Undefined index"',
        '"SQL Error:" "MySQL"',
    ],
    "Sensitive Directories": [
        'intitle:"index of /" "etc"',
        'intitle:"index of /" "private"',
        'intitle:"index of /" "logs"',
        'intitle:"index of /" "backup"',
        'intitle:"index of /" "admin"',
    ],
    "Exposed API Keys": [
        '"api_key" filetype:json',
        '"api_key" filetype:env',
        '"API_KEY" "sk-" filetype:env',
        '"aws_access_key" filetype:env',
        '"slack_token" filetype:env',
    ],
    "PHP Info": [
        'intitle:"phpinfo()"',
        'ext:php intitle:phpinfo "PHP Version"',
        'inurl:phpinfo.php',
        'intitle:"phpinfo()" "Configure Command"',
    ],
    "WordPress Specific": [
        'inurl:wp-content/uploads/',
        'inurl:wp-json/wp/v2/users',
        'intitle:"index of" wp-content',
        'inurl:wp-config.bak',
        'inurl:wp-admin "install.php"',
    ],
}


class GoogleDorker:
    name = "dork"
    description = "Generate and organize Google dork queries"

    @staticmethod
    def run(target="", domain=None, category=None):
        section("Google Dork Generator")

        info("These are search queries you can manually enter into Google or other search engines.")
        info("Submit them at your own risk and only for educational/authorized purposes.\n")

        if category:
            categories_to_show = [c for c in DORKS if category.lower() in c.lower()]
            if not categories_to_show:
                error(f"Category '{category}' not found")
                info("Available categories:")
                for cat in DORKS:
                    info(f"  - {cat}")
                return {"target": target, "error": f"Category '{category}' not found"}
        else:
            categories_to_show = list(DORKS.keys())

        for cat in categories_to_show:
            dorks = DORKS[cat]
            section(f"{cat}")
            for dork in dorks:
                if domain:
                    dork_with_domain = f"{dork} site:{domain}"
                    result("Query", dork_with_domain)
                else:
                    result("Query", dork)

            if domain:
                section(f"{cat} (URL format)")
                for dork in dorks:
                    from urllib.parse import quote
                    full_dork = f"{dork} site:{domain}" if domain else dork
                    url = f"https://www.google.com/search?q={quote(full_dork)}"
                    info(f"  {url}")

        if not domain:
            info("\nTip: Use --domain <target.com> to scope dorks to a specific domain")
        info(f"\nGenerated {sum(len(DORKS[cat]) for cat in categories_to_show)} dork query/querie(s)")
        info("Remember: For educational purposes only. Do not use against targets without permission.")

        return {"target": target, "categories_used": categories_to_show}
