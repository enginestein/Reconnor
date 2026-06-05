import json
import urllib.request
import socket
import ssl
import re
from utils.output import section, info, success, warning, error, result, table


class K8sAudit:
    description = "Advanced Kubernetes security audit: RBAC, dashboard, etcd, API server, pod security"

    K8S_API_PATHS = [
        "/api", "/api/v1", "/apis", "/apis/apps/v1", "/apis/rbac.authorization.k8s.io/v1",
        "/apis/authentication.k8s.io/v1", "/apis/authorization.k8s.io/v1",
        "/openapi/v2", "/healthz", "/version", "/api/v1/namespaces",
        "/api/v1/nodes", "/api/v1/pods", "/api/v1/secrets",
        "/api/v1/configmaps", "/api/v1/services", "/api/v1/endpoints",
        "/api/v1/persistentvolumes", "/api/v1/serviceaccounts",
        "/apis/rbac.authorization.k8s.io/v1/roles",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "/apis/rbac.authorization.k8s.io/v1/rolebindings",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "/apis/extensions/v1beta1/ingresses",
        "/apis/networking.k8s.io/v1/ingresses",
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/kube-system/secrets",
        "/api/v1/namespaces/default/pods",
        "/api/v1/namespaces/kube-system/pods",
    ]

    DASHBOARD_PATHS = [
        "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
        "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
        "/api/v1/namespaces/kubernetes-dashboard/services/http:kubernetes-dashboard:/proxy/",
        "/api/v1/namespaces/kube-system/services/http:kubernetes-dashboard:/proxy/",
    ]

    COMMON_PORTS = [443, 6443, 8443, 8080, 8001, 10250, 10255, 10257, 10259]

    @staticmethod
    def run(target="", url="", port=0, timeout=10, insecure=True, full=False, **kwargs):
        section("Kubernetes Security Audit")

        target_host = target or url or ""
        if not target_host:
            error("No target (use --target)")
            return {"error": "no target"}

        target_host = target_host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        result_data = {
            "target": target_host,
            "api_server": {"accessible": False, "version": None, "endpoints_accessible": []},
            "dashboard": {"accessible": False, "url": None},
            "kubelet": {"accessible": False, "port": None},
            "etcd": {"accessible": False, "port": None},
            "rbac": {"anonymous_access": False, "cluster_admin": False},
            "secrets_exposed": [],
            "pods_exposed": [],
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        section("API Server Discovery")
        test_ports = [port] if port else K8sAudit.COMMON_PORTS
        api_port = None

        for p in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target_host, p))
                sock.close()
                info(f"Port {p} open — testing K8s API...")
                try:
                    req = urllib.request.Request(
                        f"https://{target_host}:{p}/api",
                        headers={"Authorization": "Bearer test"},
                    )
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                        if resp.status == 200 and ("apiVersion" in body or "kind" in body or "groupVersion" in body):
                            api_port = p
                            result_data["api_server"]["accessible"] = True
                            result_data["api_server"]["version"] = p
                            success(f"K8s API server on {target_host}:{p}")
                            break
                except:
                    pass
            except:
                pass

        if not api_port:
            info("No Kubernetes API server detected on common ports")
            return result_data

        section("Endpoint Access Test")
        for path in K8sAudit.K8S_API_PATHS:
            try:
                url = f"https://{target_host}:{api_port}{path}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if resp.status == 200:
                        body = resp.read().decode("utf-8", errors="replace")[:100]
                        result_data["api_server"]["endpoints_accessible"].append(path)
                        if "secrets" in path.lower():
                            result_data["secrets_exposed"].append(path)
                            warning(f"SECRETS EXPOSED: {path}")
                        elif "pods" in path.lower():
                            result_data["pods_exposed"].append(path)
                            warning(f"PODS EXPOSED: {path}")
                        elif "rbac" in path.lower():
                            result_data["rbac"]["anonymous_access"] = True
                            warning(f"RBAC EXPOSED: {path}")
                        else:
                            info(f"Accessible: {path}")
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    info(f"Protected (403): {path}")
            except:
                pass

        if result_data["api_server"]["endpoints_accessible"]:
            warning(f"{len(result_data['api_server']['endpoints_accessible'])} endpoint(s) accessible without auth")

        section("Dashboard Check")
        for path in K8sAudit.DASHBOARD_PATHS:
            try:
                url = f"https://{target_host}:{api_port}{path}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if resp.status == 200:
                        result_data["dashboard"]["accessible"] = True
                        result_data["dashboard"]["url"] = url
                        warning(f"DASHBOARD ACCESSIBLE: {url}")
                        break
            except:
                pass

        if result_data["dashboard"]["accessible"]:
            warning("Kubernetes dashboard accessible — check for privilege escalation")

        section("Kubelet & etcd Check")
        for p in [10250, 10255]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target_host, p))
                sock.close()
                result_data["kubelet"]["accessible"] = True
                result_data["kubelet"]["port"] = p
                warning(f"Kubelet API on port {p}")
            except:
                pass

        for p in [2379, 2380]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target_host, p))
                sock.close()
                result_data["etcd"]["accessible"] = True
                result_data["etcd"]["port"] = p
                warning(f"etcd on port {p} — potential cluster compromise")
            except:
                pass

        section("K8s Audit Complete")
        if result_data["api_server"]["endpoints_accessible"]:
            warning(f"UNAUTHENTICATED API ACCESS: {len(result_data['api_server']['endpoints_accessible'])} endpoint(s)")
        if result_data["dashboard"]["accessible"]:
            warning("DASHBOARD EXPOSED: restrict with RBAC")
        if result_data["kubelet"]["accessible"]:
            warning("KUBELET EXPOSED: restrict anonymous access")
        if result_data["etcd"]["accessible"]:
            warning("ETCD EXPOSED: use TLS and restrict network access")
        if result_data["rbac"]["anonymous_access"]:
            warning("ANONYMOUS RBAC ACCESS: bind to system:anonymous")

        return result_data
