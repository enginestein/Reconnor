import sys
import shutil
import subprocess
import platform


SYSTEM_TOOLS = [
    "nmap", "whois", "openssl", "dig", "host",
]

PIP_TOOLS = [
    "sublist3r", "wafw00f", "dnsrecon", "linkfinder",
]

GO_TOOLS = {
    "amass": "github.com/owasp-amass/v3/...",
    "assetfinder": "github.com/tomnomnom/assetfinder",
    "ffuf": "github.com/ffuf/ffuf/v2",
    "gobuster": "github.com/OJ/gobuster/v3",
    "gospider": "github.com/jaeles-project/gospider",
    "hakrawler": "github.com/hakluke/hakrawler",
    "subjs": "github.com/lc/subjs",
}

APT_MAP = {
    "nmap": "nmap", "whois": "whois", "dig": "dnsutils",
    "host": "dnsutils", "openssl": "openssl",
    "whatweb": "whatweb", "gobuster": "gobuster",
}

BREW_MAP = {
    "nmap": "nmap", "whois": "whois", "dig": "bind",
    "host": "bind", "openssl": "openssl",
    "whatweb": "whatweb", "gobuster": "gobuster",
    "amass": "amass", "assetfinder": "assetfinder",
    "ffuf": "ffuf", "gospider": "gospider",
    "hakrawler": "hakrawler", "subjs": "subjs",
}


def check(name):
    return shutil.which(name) is not None


def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)


def print_step(msg):
    print(f"\n  [{msg}]")


def main(auto_yes=False):
    system = platform.system().lower()
    distro = ""
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.split("=")[1].strip().strip('"')
                        break
        except:
            pass

    print("=== Reconnor Dependency Installer ===\n")

    deps_installer = None
    pm_install = []
    if system == "linux" and distro in ("ubuntu", "debian", "kali", "linuxmint", "pop", "parrot"):
        if check("apt-get"):
            deps_installer = "apt"
            pm_install = ["apt-get", "install"]
            if auto_yes:
                pm_install.append("-y")

    elif system == "linux" and distro in ("arch", "manjaro", "endeavouros"):
        if check("pacman"):
            deps_installer = "pacman"
            pm_install = ["pacman", "-S"]
            if auto_yes:
                pm_install.append("--noconfirm")

    elif system == "darwin":
        if check("brew"):
            deps_installer = "brew"
            pm_install = ["brew", "install"]

    print_step("System packages")
    missing_sys = [t for t in SYSTEM_TOOLS if not check(t)]
    if deps_installer == "apt":
        for t in ["whatweb", "gobuster"]:
            if not check(t):
                missing_sys.append(t)
        pkg_names = list(set(APT_MAP.get(t, t) for t in missing_sys))
    elif deps_installer == "brew":
        for t in BREW_MAP:
            if not check(t) and t not in missing_sys:
                missing_sys.append(t)
        pkg_names = list(set(BREW_MAP.get(t, t) for t in missing_sys))
    else:
        pkg_names = missing_sys

    if pkg_names and deps_installer:
        print(f"  Installing: {' '.join(pkg_names)}")
        need_sudo = deps_installer in ("apt", "pacman")
        cmd = (["sudo"] if need_sudo else []) + pm_install + pkg_names
        ok, out = run(cmd, timeout=300)
        if ok:
            print("  System packages installed.")
        else:
            print(f"  Failed: {out[:300]}")
    elif pkg_names:
        print(f"  No supported package manager found. Install manually:")
        print(f"  {' '.join(pkg_names)}")
    else:
        print("  All system packages already installed.")

    print_step("Python external tools (pip)")
    missing_pip = [t for t in PIP_TOOLS if not check(t)]
    if missing_pip:
        print(f"  Installing: {' '.join(missing_pip)}")
        ok, out = run([sys.executable, "-m", "pip", "install"] + missing_pip, timeout=180)
        if ok:
            print("  Python tools installed.")
        else:
            print(f"  Failed: {out[:300]}")
    else:
        print("  All pip tools already installed.")

    print_step("Go-based tools")
    if check("go"):
        missing_go = [t for t in GO_TOOLS if not check(t)]
        if missing_go:
            for g in missing_go:
                path = GO_TOOLS[g]
                url = path.split("/...")[0] if "/..." in path else path
                print(f"  Installing {g}...")
                ok, out = run(["go", "install", url + "@latest"], timeout=300)
                if ok:
                    print(f"  {g} installed.")
                else:
                    print(f"  {g} failed: {out[:200]}")
        else:
            print("  All Go tools already installed.")
    else:
        missing_go = [t for t in GO_TOOLS if not check(t)]
        if missing_go:
            print("  Go not found. Install Go first, then:")
            for g, path in GO_TOOLS.items():
                if not check(g):
                    url = path.split("/...")[0] if "/..." in path else path
                    print(f"    go install {url}@latest")

    print("\n=== Done ===")
    still_missing = [t for t in list(SYSTEM_TOOLS) + list(GO_TOOLS.keys()) + PIP_TOOLS if not check(t)]
    if still_missing:
        print(f"Still missing: {', '.join(sorted(set(still_missing)))}")
        print("Some tools will fall back to built-in implementations.")
    else:
        print("All external tools are available.")
    print("Run 'reconnor <tool> --help' to get started.")


if __name__ == "__main__":
    auto = "-y" in sys.argv or "--yes" in sys.argv
    main(auto_yes=auto)
