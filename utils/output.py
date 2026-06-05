import sys
from colorama import init, Fore, Style

init(autoreset=True)

INFO = Fore.BLUE
SUCCESS = Fore.GREEN
WARNING = Fore.YELLOW
ERROR = Fore.RED
SECTION = Fore.CYAN + Style.BRIGHT
RESULT = Fore.WHITE + Style.BRIGHT
HIGHLIGHT = Fore.MAGENTA + Style.BRIGHT
DIM = Style.DIM

QUIET = False



BANNER = f"""{Fore.RED}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║   ██║██╔══██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
{Style.RESET_ALL}"""

DISCLAIMER = f"""
{Fore.YELLOW}
╔═══════════════════════════════════════════════════════════╗
║  DISCLAIMER: This tool is for EDUCATIONAL PURPOSES only.  ║
║  Only use on systems you OWN or have EXPLICIT PERMISSION  ║
║  to test. Unauthorized access is ILLEGAL.                 ║
╚═══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def print_banner():
    if not QUIET:
        print(BANNER)
        print(DISCLAIMER)


def info(msg):
    if not QUIET:
        print(f"{INFO}[*] {msg}{Style.RESET_ALL}")


def success(msg):
    if not QUIET:
        print(f"{SUCCESS}[+] {msg}{Style.RESET_ALL}")


def warning(msg):
    if not QUIET:
        print(f"{WARNING}[!] {msg}{Style.RESET_ALL}")


def error(msg):
    if not QUIET:
        print(f"{ERROR}[-] {msg}{Style.RESET_ALL}", file=sys.stderr)


def section(msg):
    if not QUIET:
        print(f"\n{SECTION}{'=' * 60}{Style.RESET_ALL}")
        print(f"{SECTION}  {msg}{Style.RESET_ALL}")
        print(f"{SECTION}{'=' * 60}{Style.RESET_ALL}")


def result(label, value):
    if not QUIET:
        print(f"  {RESULT}{label}:{Style.RESET_ALL} {value}")


def table(headers, rows):
    if QUIET:
        return
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    sep = "+".join("-" * (w + 2) for w in col_widths)
    header_line = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
    print(f"  {sep}")
    print(f"  {header_line}")
    print(f"  {sep}")
    for row in rows:
        line = "| " + " | ".join(str(c).ljust(col_widths[i]) for i, c in enumerate(row)) + " |"
        print(f"  {line}")
    print(f"  {sep}")
