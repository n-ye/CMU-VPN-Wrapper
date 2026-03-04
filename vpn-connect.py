#!/usr/bin/env python3
"""
School VPN Connect Tool
=======================
Opens a browser for SSO/web login, captures auth cookies,
and passes them to openconnect. Provides a live TUI dashboard
showing uptime, packet stats, and connection health.

Requirements:
    pip install playwright rich
    playwright install chromium
    openconnect must be installed (sudo apt install openconnect)

Usage:
    sudo python3 vpn_connect.py --url https://vpn.yourschool.edu
    sudo python3 vpn_connect.py --url https://vpn.yourschool.edu --cookie-name DSID
    sudo python3 vpn_connect.py --url https://vpn.yourschool.edu --server vpn.yourschool.edu
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("Error: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    sys.exit(1)


# ─── Data Models ───────────────────────────────────────────────────────────────

from Models import VPNStats

# ─── Cookie Extraction via Browser ────────────────────────────────────────────

from cookie_extractor import extract_cookies_via_browser

# ─── OpenConnect Process Management ───────────────────────────────────────────

from OpenConnect import OpenConnectRunner

# ─── TUI Dashboard ────────────────────────────────────────────────────────────

from TUI import render_dashboard, run_dashboard

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Connect to a school VPN via browser-based SSO authentication.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://vpn.school.edu
  %(prog)s --url https://vpn.school.edu --cookie-name DSID
  %(prog)s --url https://vpn.school.edu --server vpn.school.edu --protocol gp
  %(prog)s --url https://vpn.school.edu --dump-cookies   (debug: just print cookies)
        """,
    )
    parser.add_argument("--url", required=True, help="VPN portal login URL")
    parser.add_argument("--server", help="VPN server hostname (defaults to URL host)")
    parser.add_argument("--cookie-name", default=None,
                        help="Name of the auth cookie to capture (default: DSID)")
    parser.add_argument("--protocol", default="anyconnect",
                        choices=["anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"],
                        help="OpenConnect protocol (default: anyconnect)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Max seconds to wait for browser login (default: 300)")
    parser.add_argument("--dump-cookies", action="store_true",
                        help="Just print captured cookies and exit (for debugging)")
    parser.add_argument("--extra-args", nargs="*", default=[],
                        help="Extra arguments to pass to openconnect")

    args = parser.parse_args()

    # Derive server from URL if not specified
    server = args.server
    if not server:
        from urllib.parse import urlparse
        server = urlparse(args.url).hostname

    console = Console()
    console.print(Panel(
        "[bold]School VPN Connect[/bold]\n"
        f"Portal: {args.url}\n"
        f"Server: {server}\n"
        f"Protocol: {args.protocol}",
        title="◆ VPN Connect",
        border_style="rgb(30,60,120)",
    ))

    # Step 1: Browser login & cookie capture
    cookies = extract_cookies_via_browser(
        url=args.url,
        cookie_name=args.cookie_name,
        timeout=args.timeout,
    )

    if not cookies:
        console.print("[bold red]No cookies captured. Exiting.[/]")
        sys.exit(1)

    if args.dump_cookies:
        console.print("\n[bold]Captured Cookies:[/]")
        for name, value in cookies.items():
            console.print(f"  {name} = {value[:60]}{'...' if len(value) > 60 else ''}")
        sys.exit(0)

    # Step 2: Check openconnect availability
    if os.geteuid() != 0:
        console.print("[bold yellow]Warning: openconnect typically requires root. "
                      "Consider running with sudo.[/]")

    try:
        subprocess.run(["openconnect", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        console.print("[bold red]openconnect not found. Install it:[/]")
        console.print("  Ubuntu/Debian: sudo apt install openconnect")
        console.print("  macOS: brew install openconnect")
        console.print("  Fedora: sudo dnf install openconnect")
        sys.exit(1)

    # Step 3: Launch openconnect with captured cookie
    runner = OpenConnectRunner(
        server=server,
        cookies=cookies,
        cookie_name=args.cookie_name,
        protocol=args.protocol,
        extra_args=args.extra_args,
    )

    console.print(f"\n[bold cyan]Connecting to {server}...[/]\n")
    runner.start()

    # Step 4: Live dashboard
    try:
        run_dashboard(runner)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[yellow]Disconnecting...[/]")
        runner.stop()
        console.print("[bold green]Disconnected. Goodbye![/]")


if __name__ == "__main__":
    main()