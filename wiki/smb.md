# SMB Enumerator

SMB enumerator: share listing, null session, OS version, RID cycle user enum.

```
python3 main.py smb 192.168.1.1 --dump
```

**Options:**
- `--target` — Target host
- `--host` — Host alias
- `--port` — SMB port (default: 445)
- `--dump` — Full enumeration (shares + users)
- `--null-session` — Test null session
- `--list-shares` — List SMB shares
- `--enum-users` — Enumerate users
- `--timeout` — Socket timeout (default: 10)
