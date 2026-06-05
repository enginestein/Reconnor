# LDAP Scanner

LDAP scanner: anonymous bind, attribute discovery, user/group dump, DN enumeration.

```
python3 main.py ldap 192.168.1.1 --dump
```

**Options:**
- `--target` — Target host
- `--host` — Host alias
- `--port` — LDAP port (default: 389)
- `--base-dn` — LDAP base DN
- `--dump` — Dump users and groups
- `--ssl` — Use LDAPS
- `--timeout` — Socket timeout (default: 10)
