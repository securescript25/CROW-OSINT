"""Banner ASCII قابل للتخصيص لـ CROW."""
import click
from colorama import Fore, Style, init

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.CYAN}
    ▄█▄      ▄  █ ▄▄▄▄▄      ▄▄▄▄▀ ▄  █ ▄▄▄▄▄      ▄▄▄▄▀
   ▄▀   ▀▄   █  █▀   ▀   ▄▀▀▀▄▀▀▀ ▄▀  █▀   ▀   ▄▀▀▀▄▀▀▀
  █     █   █▀ █      █ ▄▀    █    █▀ █      █ ▄▀    █
  █     █   █  █      █ █     █    █  █      █ █     █
   ▀▄▄▄▄▀  █   █▄▄▄▄▀  █     █   █   █▄▄▄▄▀  █     █
{Style.BRIGHT}{Fore.YELLOW}Crow Recon OSINT Framework v0.1.0{Style.RESET_ALL}
{Fore.CYAN}────────────────────────────────────────────────────────{Fore.RESET}
"""
    click.echo(banner)
