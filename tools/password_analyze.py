import math
import re
import string
import hashlib
from utils.output import section, info, success, warning, error, result, table


class PasswordAnalyze:
    description = "Advanced password strength analyzer: entropy, patterns, common checks, crack time estimation"

    COMMON_PASSWORDS_URL = ""
    COMMON_SET = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "welcome", "shadow", "ashley", "football", "jesus", "michael", "ninja",
        "mustang", "password1", "admin", "administrator", "passw0rd", "P@ssw0rd",
        "qwerty123", "123456789", "1234567890", "111111", "000000", "7777777",
        "login", "starwars", "bailey", "access", "flower", "hottie", "loveme",
        "pass", "password123", "password1234", "pass123", "pass1234", "admin123",
    }

    @staticmethod
    def run(password="", passwords="", min_len=8, check_common=True, verbose=False, **kwargs):
        section("Password Strength Analyzer")

        passwords_to_check = []
        if password:
            passwords_to_check.append(password)
        if passwords:
            passwords_to_check.extend(p.strip() for p in passwords.split(",") if p.strip())

        if not passwords_to_check:
            error("No password(s) to analyze (use --password or --passwords)")
            return {"error": "no password"}

        section(f"Analyzing {len(passwords_to_check)} password(s)")
        results = []

        for pwd in passwords_to_check:
            analysis = PasswordAnalyze._analyze(pwd, min_len, check_common)
            results.append(analysis)

            result(f"Password: {pwd[:20] + '...' if len(pwd) > 20 else pwd}", PasswordAnalyze._format_strength(analysis["score"]))
            for key, val in analysis.items():
                if key not in ("password", "score", "crack_time"):
                    result(key.replace("_", " ").title(), str(val))
            result("Crack Time", analysis.get("crack_time", "N/A"))
            print()

        section("Analysis Complete")
        return {"passwords": results}

    @staticmethod
    def _analyze(pwd, min_len, check_common):
        result = {
            "password": pwd,
            "length": len(pwd),
            "entropy": 0,
            "score": 0,
            "crack_time": "",
            "has_uppercase": False,
            "has_lowercase": False,
            "has_digits": False,
            "has_special": False,
            "has_whitespace": False,
            "is_common": False,
            "is_leaked": False,
            "repeated_chars": False,
            "sequential": False,
            "pattern_type": "unknown",
        }

        # Character class detection
        if re.search(r"[A-Z]", pwd):
            result["has_uppercase"] = True
        if re.search(r"[a-z]", pwd):
            result["has_lowercase"] = True
        if re.search(r"\d", pwd):
            result["has_digits"] = True
        if re.search(r"[^a-zA-Z0-9\s]", pwd):
            result["has_special"] = True
        if re.search(r"\s", pwd):
            result["has_whitespace"] = True

        # Pattern detection
        if re.search(r"(.)\1{3,}", pwd):
            result["repeated_chars"] = True
            result["pattern_type"] = "repeated"

        seqs = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm",
                "abcdef", "123456", "111111", "abc123", "qwerty"]
        for seq in seqs:
            for i in range(len(seq) - 2):
                if seq[i:i+3].lower() in pwd.lower():
                    result["sequential"] = True
                    result["pattern_type"] = "sequential"
                    break
            if result["sequential"]:
                break

        # Common password check
        if check_common:
            if pwd.lower() in PasswordAnalyze.COMMON_SET:
                result["is_common"] = True
                result["pattern_type"] = "common"

            # Check HIBP-style common patterns
            if pwd.lower() in ("password", "password123", "admin", "letmein", "welcome"):
                result["is_common"] = True

        # Entropy calculation
        charset_size = 0
        if result["has_lowercase"]:
            charset_size += 26
        if result["has_uppercase"]:
            charset_size += 26
        if result["has_digits"]:
            charset_size += 10
        if result["has_special"]:
            charset_size += 33
        if result["has_whitespace"]:
            charset_size += 1

        if charset_size == 0:
            charset_size = 26

        entropy = len(pwd) * math.log2(charset_size) if len(pwd) > 0 else 0
        result["entropy"] = round(entropy, 1)

        # Scoring (0-100)
        score = 0
        if len(pwd) >= min_len:
            score += 25
        if len(pwd) >= 12:
            score += 15
        if len(pwd) >= 16:
            score += 10

        if result["has_lowercase"] and result["has_uppercase"]:
            score += 10
        if result["has_digits"]:
            score += 10
        if result["has_special"]:
            score += 15
        if result["has_lowercase"] and result["has_uppercase"] and result["has_digits"] and result["has_special"]:
            score += 15

        if result["is_common"]:
            score = max(score - 50, 0)
        if result["repeated_chars"]:
            score -= 15
        if result["sequential"]:
            score -= 10

        result["score"] = max(min(score, 100), 0)

        # Crack time estimation
        result["crack_time"] = PasswordAnalyze._estimate_crack_time(entropy, len(pwd))

        return result

    @staticmethod
    def _estimate_crack_time(entropy, length):
        if length == 0:
            return "instant"
        patterns_per_sec = {
            10000000000: "seconds",
            100000000000: "minutes",
            1000000000000: "hours",
            10000000000000: "days",
            100000000000000: "months",
            1000000000000000: "years",
            10000000000000000: "centuries",
        }

        attempts = 2**entropy
        for threshold, period in sorted(patterns_per_sec.items()):
            if attempts < threshold:
                return f"{period} (10B/sec)"
        return "centuries (10B/sec)"

    @staticmethod
    def _format_strength(score):
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
