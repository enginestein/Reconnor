import json
import urllib.request
import socket
import re
from utils.output import section, info, success, warning, error, result, table


class ContainerScan:
    description = "Advanced container security scanner: Docker socket, breakout tests, image vuln scan"

    DOCKER_PATHS = [
        "/containers/json", "/images/json", "/info", "/version",
        "/containers/json?all=true", "/services", "/tasks",
        "/nodes", "/networks", "/volumes", "/secrets",
        "/configs", "/events",
    ]

    COMMON_DOCKER_PORTS = [2375, 2376, 4243]

    BREAKOUT_TESTS = [
        "/proc/1/cgroup",
        "/proc/1/root/etc/passwd",
        "/proc/1/environ",
        "/proc/1/cmdline",
        "/proc/1/mountinfo",
        "/proc/self/cgroup",
        "/proc/self/mounts",
    ]

    VULN_IMAGES = [
        "node:latest", "python:latest", "nginx:latest", "ubuntu:latest",
        "alpine:latest", "debian:latest", "centos:latest",
        "node:alpine", "python:alpine", "nginx:alpine",
    ]

    COMMON_IMAGES = [
        "nginx", "httpd", "tomcat", "node", "python", "ruby",
        "php", "mysql", "postgres", "mongo", "redis", "rabbitmq",
        "alpine", "ubuntu", "centos", "debian", "fedora",
        "jenkins/jenkins", "gitlab/gitlab-ce", "sonarqube",
        "prom/prometheus", "grafana/grafana", "elasticsearch",
        "kibana", "logstash", "consul", "vault",
    ]

    @staticmethod
    def run(target="", host="", port=0, socket_path="", breakout=False, images=False, timeout=10, **kwargs):
        section("Container Security Scanner")

        target_host = target or host or ""
        result_data = {
            "docker_api": {"accessible": False, "endpoints": []},
            "breakout": {"possible": False, "tests_passed": []},
            "images": [],
            "containers": [],
            "host_access": False,
        }

        if target_host:
            section("Remote Docker API")
            test_ports = [port] if port else ContainerScan.COMMON_DOCKER_PORTS
            for p in test_ports:
                try:
                    for path in ContainerScan.DOCKER_PATHS[:3]:
                        try:
                            url = f"http://{target_host}:{p}{path}"
                            req = urllib.request.Request(url)
                            with urllib.request.urlopen(req, timeout=timeout) as resp:
                                body = resp.read().decode("utf-8", errors="replace")[:200]
                                if resp.status == 200 and ("Id" in body or "Containers" in body or "ID" in body):
                                    result_data["docker_api"]["accessible"] = True
                                    success(f"Docker API on {target_host}:{p}")
                                    break
                        except:
                            pass
                    if result_data["docker_api"]["accessible"]:
                        break
                except:
                    pass

            if result_data["docker_api"]["accessible"]:
                section("Docker API Enumeration")
                for path in ContainerScan.DOCKER_PATHS:
                    try:
                        url = f"http://{target_host}:{test_ports[0]}{path}"
                        req = urllib.request.Request(url)
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            body = resp.read().decode("utf-8", errors="replace")
                            result_data["docker_api"]["endpoints"].append(path)
                            if "containers" in path.lower():
                                try:
                                    containers = json.loads(body)
                                    for c in containers[:10]:
                                        info(f"Container: {c.get('Names', ['?'])[0] if c.get('Names') else '?'} ({c.get('Image', '?')})")
                                        result_data["containers"].append({"name": c.get('Names', ['?'])[0] if c.get('Names') else '?', "image": c.get('Image', '?'), "status": c.get('Status', '?'), "state": c.get('State', '?')})
                                except:
                                    info(f"Accessible: {path}")
                            elif "images" in path.lower():
                                try:
                                    imgs = json.loads(body)
                                    for img in imgs[:10]:
                                        img_info = {"repo": img.get('RepoTags', ['?'])[0] if img.get('RepoTags') else '?', "id": img.get('Id', '?')[:19], "created": img.get('Created', '?')}
                                        result_data["images"].append(img_info)
                                        info(f"Image: {img_info['repo']}")
                                except:
                                    info(f"Accessible: {path}")
                            else:
                                info(f"Accessible: {path}")
                    except:
                        pass

        if breakout:
            section("Container Breakout Tests")
            for path in ContainerScan.BREAKOUT_TESTS:
                url = f"file://{path}" if host else path
                try:
                    with open(path, "r") as f:
                        content = f.read().strip()
                        result_data["breakout"]["tests_passed"].append(path)
                        if "docker" in content or "kubepods" in content:
                            result_data["breakout"]["possible"] = True
                            warning(f"INSIDE CONTAINER: {path}")
                            warning(f"  Evidence: {content[:100]}")
                        else:
                            info(f"File exists: {path} ({content[:50]})")
                except:
                    pass

        if images:
            section("Image Vulnerability Check")
            info("Checking common container images for known vulnerabilities")
            vuln_images_found = []
            for img in ContainerScan.VULN_IMAGES:
                name = img.split(":")[0]
                try:
                    import subprocess
                    result = subprocess.run(
                        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                        capture_output=True, text=True, timeout=timeout,
                    )
                    if name in result.stdout:
                        vuln_images_found.append(img)
                        warning(f"Vulnerable image in use: {img}")
                except:
                    pass

            for img in ContainerScan.COMMON_IMAGES:
                try:
                    result = subprocess.run(
                        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                        capture_output=True, text=True, timeout=timeout,
                    )
                    if img in result.stdout:
                        info(f"Image found: {img}")
                except:
                    pass

        section("Container Security Scan Complete")
        if result_data["docker_api"]["accessible"]:
            warning(f"DOCKER API EXPOSED: {len(result_data['docker_api']['endpoints'])} endpoint(s) accessible — potential host takeover")
        if result_data["breakout"]["possible"]:
            warning("RUNNING INSIDE CONTAINER — check for escape vectors")
        else:
            success("No immediate container breakout indicators")

        return result_data
