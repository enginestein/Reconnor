# NFS Enumerator

NFS enumerator: export listing, mount checking, permission analysis, rpcbind query.

```
python3 main.py nfs 192.168.1.1
```

**Options:**
- `--target` — Target host
- `--host` — Host alias
- `--port` — NFS port (default: 2049)
- `--timeout` — Socket timeout (default: 10)
