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
    print(BANNER)
    print(DISCLAIMER)


def info(msg):
    print(f"{INFO}[*] {msg}{Style.RESET_ALL}")


def success(msg):
    print(f"{SUCCESS}[+] {msg}{Style.RESET_ALL}")


def warning(msg):
    print(f"{WARNING}[!] {msg}{Style.RESET_ALL}")


def error(msg):
    print(f"{ERROR}[-] {msg}{Style.RESET_ALL}", file=sys.stderr)


def section(msg):
    print(f"\n{SECTION}{'=' * 60}{Style.RESET_ALL}")
    print(f"{SECTION}  {msg}{Style.RESET_ALL}")
    print(f"{SECTION}{'=' * 60}{Style.RESET_ALL}")


def result(label, value):
    print(f"  {RESULT}{label}:{Style.RESET_ALL} {value}")


def table(headers, rows):
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
