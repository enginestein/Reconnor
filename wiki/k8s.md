# Kubernetes Auditor

Kubernetes security audit: RBAC, dashboard, etcd, kubelet, API server, pod/secret exposure.

```
python3 main.py k8s 192.168.1.100 --full
```

**Options:**
- `--target` — Target hostname/IP
- `--url` — Target URL (alias)
- `--port` — API server port
- `--full` — Full audit
- `--insecure` — Skip TLS verification
- `--timeout` — Socket timeout (default: 10)
