# SNMP Enumerator

SNMP enumerator: community string brute force, MIB tree walk, interface/user extraction.

```
python3 main.py snmp 192.168.1.1 --walk
```

**Options:**
- `--target` — Target host
- `--host` — Host alias
- `--community` — SNMP community string to use
- `--walk` — Walk MIB tree (interfaces, users, processes)
- `--port` — SNMP port (default: 161)
- `--timeout` — Socket timeout (default: 5)
