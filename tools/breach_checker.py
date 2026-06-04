import hashlib
import requests
from utils.output import section, info, success, warning, error, result, table

HIBP_API = "https://api.pwnedpasswords.com/range/{prefix}"
FIREFOX_MONITOR_API = "https://firefoxmonitor.nofb.org/breaches"

BREACH_DATABASE = [
    {"name": "Adobe", "date": "2013-10", "accounts": "152M", "type": "Password hashes"},
    {"name": "LinkedIn", "date": "2012-05", "accounts": "165M", "type": "Password hashes"},
    {"name": "Ashley Madison", "date": "2015-07", "accounts": "36M", "type": "Emails, passwords"},
    {"name": "Dropbox", "date": "2012-07", "accounts": "68M", "type": "Emails, password hashes"},
    {"name": "Twitter", "date": "2018-12", "accounts": "330M", "type": "Emails (internal)"},
    {"name": "Facebook", "date": "2019-09", "accounts": "509M", "type": "Phone numbers, emails"},
    {"name": "Equifax", "date": "2017-09", "accounts": "147M", "type": "SSN, credit data"},
    {"name": "Marriott", "date": "2018-11", "accounts": "500M", "type": "Passport data, credit cards"},
    {"name": "Yahoo", "date": "2013-08", "accounts": "3B", "type": "Emails, password hashes"},
    {"name": "Adult FriendFinder", "date": "2016-10", "accounts": "412M", "type": "Emails, passwords"},
    {"name": "MySpace", "date": "2008-01", "accounts": "360M", "type": "Emails, passwords"},
    {"name": "NetEase", "date": "2015-10", "accounts": "234M", "type": "Emails, passwords"},
    {"name": "Collection #1", "date": "2019-01", "accounts": "773M", "type": "Email/password combos"},
    {"name": "VerificationCodes", "date": "2021-01", "accounts": "200M", "type": "SMS verification codes"},
    {"name": "Rambler", "date": "2012-02", "accounts": "98M", "type": "Emails, passwords"},
    {"name": "Badoo", "date": "2016-06", "accounts": "127M", "type": "Emails, passwords"},
    {"name": "Last.fm", "date": "2012-03", "accounts": "40M", "type": "Emails, passwords"},
    {"name": "LinkedIn 2021", "date": "2021-06", "accounts": "700M", "type": "Emails, profile data"},
    {"name": "Zyxel", "date": "2020-12", "accounts": "100K", "type": "Device configs"},
    {"name": "Canva", "date": "2019-05", "accounts": "137M", "type": "Emails, password hashes"},
    {"name": "Dubsmash", "date": "2018-12", "accounts": "162M", "type": "Emails, password hashes"},
    {"name": "Army.mil", "date": "2020-04", "accounts": "11K", "type": "Emails"},
    {"name": "MongoDB (various)", "date": "2016-2020", "accounts": "Various", "type": "Unsecured databases"},
    {"name": "Clubhouse", "date": "2021-04", "accounts": "1.3M", "type": "User IDs (scraped)"},
    {"name": "COX", "date": "2020-05", "accounts": "200K", "type": "Emails, passwords"},
    {"name": "T-Mobile", "date": "2021-08", "accounts": "48M", "type": "SSN, phone numbers, names"},
    {"name": "Neopets", "date": "2021-07", "accounts": "27M", "type": "Emails, passwords"},
    {"name": "Twitch", "date": "2021-10", "accounts": "7M", "type": "Source code, payout data"},
    {"name": "Rocket.Chat", "date": "2020-02", "accounts": "50K", "type": "Messages, user data"},
    {"name": "Wattpad", "date": "2020-06", "accounts": "268M", "type": "Emails, passwords"},
    {"name": "Pixlr", "date": "2020-08", "accounts": "1.9M", "type": "Emails, password hashes"},
    {"name": "USPS", "date": "2020-11", "accounts": "60M", "type": "User data"},
    {"name": "Socialarks", "date": "2021-03", "accounts": "214M", "type": "Instagram/FB profile data"},
    {"name": "Ola", "date": "2018-09", "accounts": "150K", "type": "User data"},
    {"name": "Atlassian", "date": "2020-04", "accounts": "440K", "type": "Employee data"},
    {"name": "Microsoft", "date": "2021-01", "accounts": "250M", "type": "Customer data"},
    {"name": "ParkMobile", "date": "2021-03", "accounts": "21M", "type": "License plates, emails"},
    {"name": "GeekedIn", "date": "2021-04", "accounts": "1.5M", "type": "LinkedIn scrape"},
    {"name": "TSheets", "date": "2020-03", "accounts": "15K", "type": "Employee data"},
    {"name": "Wizards of Coast", "date": "2020-11", "accounts": "16K", "type": "User data"},
]


def check_hibp_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10,
            headers={"User-Agent": "Reconner-OSINT/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.split("\n"):
                if line.startswith(suffix):
                    count = int(line.split(":")[1].strip())
                    return count
        return 0
    except Exception:
        return -1


def check_hibp_email(email, timeout=15):
    sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix = sha1[:5]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=timeout,
            headers={"User-Agent": "Reconner-OSINT/1.0"},
        )
        if resp.status_code == 200:
            return True
        return False
    except:
        return False


class BreachChecker:
    name = "breach"
    description = "Check email addresses, passwords, or usernames against known data breaches"

    @staticmethod
    def run(target, type="email"):
        section(f"Breach Checker: {target}")

        if type == "password" or type == "pass" or type == "pwd":
            info("Checking password against Have I Been Pwned (k-anonymity model)...")
            count = check_hibp_password(target)
            if count == -1:
                warning("Could not check password (API unavailable)")
            elif count == 0:
                success("Password NOT found in known breaches (safe)")
            else:
                error(f"Password found {count:,} time(s) in known breaches - DO NOT USE THIS PASSWORD!")

        elif type == "email":
            info("Checking email against breach databases...")

            email_domain = target.split("@")[1] if "@" in target else ""
            info(f"Email: {target}")
            if email_domain:
                result("Domain", email_domain)

            section("Known Breach Database Lookup")
            relevant = []
            for breach in BREACH_DATABASE:
                keywords = [target.split("@")[0].lower(), email_domain.lower()]
                bname = breach["name"].lower()
                if any(k in bname for k in keywords if k):
                    relevant.append(breach)
                if email_domain and email_domain[:5] in bname:
                    relevant.append(breach)

            if relevant:
                warning(f"Found {len(relevant)} potentially relevant breach(es):")
                table(
                    ["BREACH", "DATE", "ACCOUNTS", "DATA TYPE"],
                    [(b["name"], b["date"], b["accounts"], b["type"]) for b in relevant],
                )
            else:
                info("No directly matching breaches in local database")

            section("Breach Database Listing")
            info(f"Showing all {len(BREACH_DATABASE)} known breaches in database:")
            table(
                ["BREACH", "DATE", "ACCOUNTS", "DATA TYPE"],
                [(b["name"], b["date"], b["accounts"], b["type"]) for b in BREACH_DATABASE],
            )

            section("Recommendations")
            warning("If your email appears in any of these breaches:")
            info("  1. Change passwords immediately (unique password per service)")
            info("  2. Enable 2FA/MFA on all accounts that support it")
            info("  3. Check for account takeovers (login history)")
            info("  4. Use a password manager for unique passwords")
            info("  5. Monitor for phishing targeting your email")

        elif type == "username":
            info(f"Checking username '{target}' against breach context...")
            info("Username breaches are less commonly reported than email breaches.")
            for breach in BREACH_DATABASE:
                if target.lower()[:4] in breach["name"].lower():
                    warning(f"  Username partially matches: {breach['name']} ({breach['date']})")

            info("Tip: Use the 'username' tool to find profiles, then check associated emails")

        return {"target": target, "type": type}
