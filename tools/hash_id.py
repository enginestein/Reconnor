import hashlib
import re
import base64
from utils.output import section, info, success, warning, error, result, table


class HashID:
    description = "Advanced hash identifier and cracker: 50+ hash types, wordlist cracking, hash format detection"

    PATTERNS = [
        ("MD5", 32, "^[a-f0-9]{32}$", False),
        ("MD4", 32, "^[a-f0-9]{32}$", False),
        ("NTLM", 32, "^[a-f0-9]{32}$", False),
        ("SHA-1", 40, "^[a-f0-9]{40}$", False),
        ("SHA-224", 56, "^[a-f0-9]{56}$", False),
        ("SHA-256", 64, "^[a-f0-9]{64}$", False),
        ("SHA-384", 96, "^[a-f0-9]{96}$", False),
        ("SHA-512", 128, "^[a-f0-9]{128}$", False),
        ("SHA-512/256", 64, "^[a-f0-9]{64}$", False),
        ("SHA3-224", 56, "^[a-f0-9]{56}$", False),
        ("SHA3-256", 64, "^[a-f0-9]{64}$", False),
        ("SHA3-384", 96, "^[a-f0-9]{96}$", False),
        ("SHA3-512", 128, "^[a-f0-9]{128}$", False),
        ("Blake2b-256", 64, "^[a-f0-9]{64}$", False),
        ("Blake2b-512", 128, "^[a-f0-9]{128}$", False),
        ("Whirlpool", 128, "^[a-f0-9]{128}$", False),
        ("RIPEMD-128", 32, "^[a-f0-9]{32}$", False),
        ("RIPEMD-160", 40, "^[a-f0-9]{40}$", False),
        ("RIPEMD-256", 64, "^[a-f0-9]{64}$", False),
        ("RIPEMD-320", 80, "^[a-f0-9]{80}$", False),
        ("GOST R 34.11-94", 64, "^[a-f0-9]{64}$", False),
        ("CRC32", 8, "^[a-f0-9]{8}$", False),
        ("Adler32", 8, "^[a-f0-9]{8}$", False),
        ("MD5 Crypt", 34, r"^\$1\$[a-z0-9/.]{8}\$[a-z0-9/.]{22}$", False),
        ("SHA-512 Crypt", 106, r"^\$6\$[a-z0-9/.]{8,16}\$[a-z0-9/.]{86}$", False),
        ("SHA-256 Crypt", 74, r"^\$5\$[a-z0-9/.]{8,16}\$[a-z0-9/.]{43}$", False),
        ("bcrypt", 60, r"^\$2[aby]\$\d{2}\$[a-z0-9/.]{53}$", False),
        ("bcrypt", 29, r"^\$2[aby]\$\d{2}\$[a-z0-9/.]{22}$", False),
        ("scrypt", 115, r"^\$7\$[a-z0-9/.]{107}$", False),
        ("Argon2", 96, r"^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-z0-9/+=]+\$[a-z0-9/+=]+$", False),
        ("LM Hash", 32, "^[a-f0-9]{32}$", False),
        ("NT Hash", 32, "^[a-f0-9]{32}$", False),
        ("MySQL < 4.1", 16, "^[a-f0-9]{16}$", False),
        ("MySQL 5", 41, "^\*[a-f0-9]{40}$", False),
        ("PostgreSQL MD5", 35, "^md5[a-f0-9]{32}$", False),
        ("Oracle 10g", 40, "^[a-f0-9]{40}$", False),
        ("Oracle 11g", 20, "^S:[a-f0-9]{40}$", False),
        ("Oracle 12c", 60, "^[a-f0-9]{60}$", False),
        ("MSSQL 2000", 44, "^0x[a-f0-9]{40}$", False),
        ("MSSQL 2005", 54, "^0x[a-f0-9]{40}[a-f0-9]{8}$", False),
        ("MSSQL 2012", 62, "^0x[a-f0-9]{60}$", False),
        ("SHA-256 Salted", None, r"^[a-f0-9]{64}:[\w.-]+$", False),
        ("SHA-512 Salted", None, r"^[a-f0-9]{128}:[\w.-]+$", False),
        ("PBKDF2-HMAC-SHA256", None, r"^[a-f0-9]{64}:[\w.:-]+:\d+$", False),
        ("PBKDF2-HMAC-SHA512", None, r"^[a-f0-9]{128}:[\w.:-]+:\d+$", False),
        ("Django PBKDF2", None, r"^pbkdf2_sha256\$", False),
        ("Django Argon2", None, r"^argon2\$", False),
        ("Django BCrypt", None, r"^bcrypt\$", False),
        ("Bcrypt", None, r"^\$2[aby]\$", False),
        ("Bitcoin WIF", 51, "^[5KL][1-9A-HJ-NP-Za-km-z]{50}$", False),
        ("Ethereum", 42, "^0x[a-f0-9]{40}$", False),
        ("JWT", None, r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$", False),
        ("Base64", None, r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", True),
        ("Base64 URL", None, r"^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$", True),
        ("Hex", None, r"^[a-f0-9]+$", True),
        ("UUID", 36, r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", False),
        ("WordPress MD5", 34, r"^\$P\$[a-z0-9/.]{31}$", False),
        ("phppass", 34, r"^\$[PH]\$[a-z0-9/.]{31}$", False),
        ("Unix DES", 13, r"^[a-z0-9/.]{13}$", False),
        ("Unix MD5", 34, r"^\$1\$[a-z0-9/.]{8}\$[a-z0-9/.]{22}", False),
        ("DCC2", None, r"^[a-f0-9]{32}:[a-z0-9]+$", False),
        ("Kerberos 5 TGS", None, r"^\$krb5tgs\$", False),
        ("Kerberos 5 AS", None, r"^\$krb5asrep\$", False),
        ("AS-REP", None, r"^\$krb5asrep\$", False),
        ("DPAPI", None, r"^\$DPAPImk\$", False),
        ("Chrome GP3", None, r"^[a-f0-9]{32}\.[a-f0-9]{32}$", False),
        ("Firefox", None, r"^[a-f0-9]{32}\.[a-f0-9]{32}\.[a-f0-9]{32}$", False),
        ("Cisco Type 5", 40, r"^\$5\$[a-z0-9/.]{19}\$[a-z0-9/.]{19}$", False),
        ("Cisco Type 7", None, r"^07[a-f0-9]+$", False),
        ("Juniper IX", None, r"^\$9\$", False),
        ("GNU Shadow", None, r"^\$[156]\$", False),
    ]

    COMMON_WORDLIST = [
        "password", "123456", "admin", "welcome", "letmein", "qwerty",
        "monkey", "dragon", "master", "12345678", "abc123", "password123",
        "passw0rd", "P@ssw0rd", "shadow", "sunshine", "trustno1",
        "football", "baseball", "iloveyou", "secret", "changeme",
    ]

    @staticmethod
    def run(hash="", hashes="", crack=False, wordlist="", show_info=False, **kwargs):
        section("Hash Identifier & Cracker")

        hashes_to_check = []
        if hash:
            hashes_to_check.append(hash)
        if hashes:
            hashes_to_check.extend(h.strip() for h in hashes.split(",") if h.strip())

        if not hashes_to_check:
            error("No hash(es) provided (use --hash or --hashes)")
            return {"error": "no hash"}

        result_data = {"hashes": []}

        for h in hashes_to_check:
            h = h.strip()
            section(f"Analyzing: {h[:50]}...")

            matches = []
            for name, length, pattern, variable in HashID.PATTERNS:
                if length and len(h) == length:
                    if re.match(pattern, h, re.I):
                        matches.append(name)
                elif not length:
                    if re.match(pattern, h, re.I):
                        matches.append(name)

            if not matches:
                matches.append("Unknown hash type")
                info("Could not identify hash type")

            hash_entry = {
                "hash": h,
                "possible_types": matches[:5],
                "all_types": matches,
                "length": len(h),
                "cracked": False,
                "plaintext": None,
            }

            result_data["hashes"].append(hash_entry)
            result("Length", str(len(h)))
            result("Possible Type(s)", ", ".join(matches[:5]))

            if len(matches) > 5:
                info(f"... and {len(matches)-5} more possible types")

            if crack:
                section(f"Cracking: {h[:40]}...")
                words = HashID.COMMON_WORDLIST
                if wordlist:
                    try:
                        with open(wordlist) as f:
                            words = [line.strip() for line in f if line.strip()]
                        info(f"Loaded {len(words)} words from {wordlist}")
                    except:
                        warning(f"Cannot open {wordlist}, using defaults")

                cracked = False
                for candidate in words:
                    if HashID._check_candidate(h, candidate):
                        hash_entry["cracked"] = True
                        hash_entry["plaintext"] = candidate
                        success(f"CRACKED: {h[:30]}... = {candidate}")
                        cracked = True
                        break

                if not cracked:
                    warning("Not cracked with current wordlist")

            if show_info:
                section("Hash Information")
                info(f"  Bit length: {len(h) * 4}")
                info(f"  Encoding: {'Base64' if re.match(r'^[A-Za-z0-9+/=]+$', h) else 'Hex' if re.match(r'^[a-f0-9]+$', h) else 'Mixed'}")

        section("Hash Analysis Complete")
        cracked_count = sum(1 for h in result_data["hashes"] if h["cracked"])
        if cracked_count:
            success(f"Cracked {cracked_count}/{len(hashes_to_check)} hash(es)")

        return result_data

    @staticmethod
    def _check_candidate(h, candidate):
        try:
            if hashlib.md5(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.sha1(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.sha256(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.sha512(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.sha224(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.sha384(candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.new("sha3_256", candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.new("sha3_512", candidate.encode()).hexdigest() == h.lower():
                return True
            if hashlib.new("blake2b", candidate.encode()).hexdigest() == h.lower():
                return True
        except:
            pass
        return False
