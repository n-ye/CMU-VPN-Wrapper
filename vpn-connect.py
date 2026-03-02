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

@dataclass
class VPNStats:
    """Tracks VPN connection statistics parsed from openconnect output."""
    connected_at: Optional[datetime] = None
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    errors_in: int = 0
    errors_out: int = 0
    server: str = ""
    local_ip: str = ""
    remote_ip: str = ""
    dns_servers: list = field(default_factory=list)
    cstp_cipher: str = ""
    dtls_cipher: str = ""
    status: str = "Disconnected"
    last_update: Optional[datetime] = None

    @property
    def uptime(self) -> str:
        if not self.connected_at:
            return "00:00:00"
        delta = datetime.now() - self.connected_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def bytes_in_human(self) -> str:
        return self._human_bytes(self.bytes_in)

    @property
    def bytes_out_human(self) -> str:
        return self._human_bytes(self.bytes_out)

    @staticmethod
    def _human_bytes(b: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"


# ─── Cookie Extraction via Browser ────────────────────────────────────────────

def extract_cookies_via_browser(
    url: str,
    cookie_name: Optional[str] = None,
    timeout: int = 300,
) -> dict:
    """
    Opens a Chromium browser window for the user to log in.
    After login, extracts cookies from the browser context.

    Args:
        url: The VPN portal URL to open.
        cookie_name: Specific cookie to wait for (e.g., 'DSID', 'webvpn').
                     If None, captures all cookies after the user closes the browser.
        timeout: Max seconds to wait for login.

    Returns:
        dict of cookie_name -> cookie_value
    """
    console = Console()
    cookies_result = {}

    console.print(f"\n[bold cyan]Opening browser to:[/] {url}")
    console.print("[yellow]Please log in. The browser will auto-close once the auth cookie is detected.[/]")
    if not cookie_name:
        console.print("[yellow]Or close the browser manually when done logging in.[/]")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome",
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        page.goto(url, wait_until="domcontentloaded")

        start = time.time()
        detected = False

        while time.time() - start < timeout:
            try:
                all_cookies = context.cookies()
            except Exception:
                # Browser was closed by user
                break
            

            cookie_map = {c["name"]: c["value"] for c in all_cookies}

            if cookie_name:
                if cookie_name in cookie_map:
                    console.print(f"\n[bold green]✓ Cookie '{cookie_name}' captured![/]")
                    cookies_result = cookie_map
                    detected = True
                    break
            else:
                # Heuristic: detect common VPN auth cookies
                vpn_cookie_names = [
                    "DSID", "webvpn", "webvpnc", "SVPNCOOKIE",
                    "portal", "AUTH", "session", "token",
                ]
                for name in vpn_cookie_names:
                    if name in cookie_map:
                        console.print(f"\n[bold green]✓ Detected auth cookie: {name}[/]")
                        cookies_result = cookie_map
                        detected = True
                        break
                    if detected:
                        break

            if detected:
                break

            time.sleep(1)

        if not detected and not cookies_result:
            # Grab whatever cookies exist
            try:
                all_cookies = context.cookies()
                cookies_result = {c["name"]: c["value"] for c in all_cookies}
            except Exception:
                pass

        try:
            browser.close()
        except Exception:
            pass

    if not cookies_result:
        console.print("[bold red]✗ No cookies captured. Login may have failed or timed out.[/]")
    else:
        console.print(f"[green]Captured {len(cookies_result)} cookie(s).[/]")

    return cookies_result


# ─── OpenConnect Process Management ───────────────────────────────────────────

class OpenConnectRunner:
    """Manages the openconnect subprocess and parses its output for stats."""

    def __init__(self, server: str, cookies: dict, cookie_name: str,
                 protocol: str = "anyconnect", extra_args: list = None):
        self.server = server
        self.cookies = cookies
        self.cookie_name = cookie_name
        self.protocol = protocol
        self.extra_args = extra_args or []
        self.process: Optional[subprocess.Popen] = None
        self.stats = VPNStats(server=server)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def build_command(self) -> list:
        cookie_value = self.cookies.get(self.cookie_name, "")
        if not cookie_value:
            # Fallback: join all cookies
            cookie_value = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        cmd = [
            "openconnect",
            "--protocol", self.protocol,
            f"--cookie={cookie_value}",
            "--verbose",
            "--timestamp",
        ]
        cmd.extend(self.extra_args)
        cmd.append(self.server)
        return cmd

    def start(self):
        cmd = self.build_command()
        self.stats.status = "Connecting..."

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

        self._stats_thread = threading.Thread(target=self._poll_interface_stats, daemon=True)
        self._stats_thread.start()

    def stop(self):
        self._stop_event.set()
        if self.process:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.stats.status = "Disconnected"

    def _read_output(self):
        """Parse openconnect stdout for connection info."""
        for line in self.process.stdout:
            line = line.strip()
            if self._stop_event.is_set():
                break

            with self._lock:
                # Detect successful connection
                if "Connected" in line and "SSL" in line:
                    self.stats.status = "Connected"
                    self.stats.connected_at = datetime.now()

                if "ESP session established" in line or "DTLS connected" in line:
                    self.stats.status = "Connected (DTLS)"

                # Parse IPs
                m = re.search(r"Got (?:address|IPv4) ([\d.]+)", line)
                if m:
                    self.stats.local_ip = m.group(1)

                # DNS
                m = re.search(r"Got DNS ([\d.]+)", line)
                if m:
                    if m.group(1) not in self.stats.dns_servers:
                        self.stats.dns_servers.append(m.group(1))

                # Ciphers
                m = re.search(r"CSTP connected.*cipher (.+)", line)
                if m:
                    self.stats.cstp_cipher = m.group(1)

                m = re.search(r"DTLS connected.*cipher (.+)", line)
                if m:
                    self.stats.dtls_cipher = m.group(1)

                # Disconnect detection
                if "Disconnected" in line or "Failed" in line:
                    if "Connected" not in self.stats.status or "retry" not in line.lower():
                        self.stats.status = "Disconnected"

        # Process ended
        with self._lock:
            if self.stats.status != "Disconnected":
                self.stats.status = "Disconnected"

    def _poll_interface_stats(self):
        """Poll /proc/net/dev or `ip -s link` for tun interface stats."""
        while not self._stop_event.is_set():
            time.sleep(2)
            try:
                result = subprocess.run(
                    ["ip", "-s", "link", "show", "type", "tun"],
                    capture_output=True, text=True, timeout=5,
                )
                output = result.stdout

                # Also try specific tun devices
                if not output.strip():
                    for dev in ["tun0", "tun1", "utun0"]:
                        result = subprocess.run(
                            ["ip", "-s", "link", "show", dev],
                            capture_output=True, text=True, timeout=5,
                        )
                        if result.returncode == 0:
                            output = result.stdout
                            break

                if not output.strip():
                    # Fallback: parse /proc/net/dev
                    output = self._parse_proc_net_dev()
                    continue

                self._parse_ip_stats(output)

            except Exception:
                pass

    def _parse_ip_stats(self, output: str):
        """Parse `ip -s link` output for RX/TX bytes and packets."""
        lines = output.split("\n")
        rx_line = None
        tx_line = None

        for i, line in enumerate(lines):
            if "RX:" in line and i + 1 < len(lines):
                rx_line = lines[i + 1].strip()
            if "TX:" in line and i + 1 < len(lines):
                tx_line = lines[i + 1].strip()

        with self._lock:
            if rx_line:
                parts = rx_line.split()
                if len(parts) >= 3:
                    self.stats.bytes_in = int(parts[0])
                    self.stats.packets_in = int(parts[1])
                    self.stats.errors_in = int(parts[2])

            if tx_line:
                parts = tx_line.split()
                if len(parts) >= 3:
                    self.stats.bytes_out = int(parts[0])
                    self.stats.packets_out = int(parts[1])
                    self.stats.errors_out = int(parts[2])

            self.stats.last_update = datetime.now()

    def _parse_proc_net_dev(self):
        """Fallback: read /proc/net/dev for tun interface stats."""
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if "tun" in line:
                        parts = line.split()
                        iface = parts[0].rstrip(":")
                        with self._lock:
                            self.stats.bytes_in = int(parts[1])
                            self.stats.packets_in = int(parts[2])
                            self.stats.errors_in = int(parts[3])
                            self.stats.bytes_out = int(parts[9])
                            self.stats.packets_out = int(parts[10])
                            self.stats.errors_out = int(parts[11])
                            self.stats.last_update = datetime.now()
                        return
        except FileNotFoundError:
            pass


# ─── TUI Dashboard ────────────────────────────────────────────────────────────

def render_dashboard(stats: VPNStats) -> Layout:
    """Build the Rich TUI layout for the VPN dashboard."""

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    # ── Header ──
    status_color = {
        "Connected": "bold green",
        "Connected (DTLS)": "bold green",
        "Connecting...": "bold yellow",
        "Disconnected": "bold red",
    }.get(stats.status, "bold white")

    header_text = Text()
    header_text.append("  ◆ VPN CONNECT  ", style="bold white on rgb(30,60,120)")
    header_text.append(f"  {stats.status}  ", style=status_color)
    header_text.append(f"  ⏱ {stats.uptime}", style="bold cyan")

    layout["header"].update(Panel(header_text, style="rgb(30,60,120)"))

    # ── Body ──
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1),
    )

    # Left panel: Connection Info
    conn_table = Table(
        show_header=False, box=box.SIMPLE_HEAVY, expand=True,
        title="[bold]Connection", title_style="bold cyan",
        border_style="rgb(60,100,160)",
    )
    conn_table.add_column("Key", style="dim", width=16)
    conn_table.add_column("Value", style="bold white")

    conn_table.add_row("Server", stats.server or "—")
    conn_table.add_row("Local IP", stats.local_ip or "—")
    conn_table.add_row("DNS", ", ".join(stats.dns_servers) if stats.dns_servers else "—")
    conn_table.add_row("CSTP Cipher", stats.cstp_cipher or "—")
    conn_table.add_row("DTLS Cipher", stats.dtls_cipher or "—")
    conn_table.add_row("Uptime", stats.uptime)

    layout["left"].update(Panel(conn_table, border_style="rgb(60,100,160)"))

    # Right panel: Traffic Stats
    traffic_table = Table(
        show_header=True, box=box.SIMPLE_HEAVY, expand=True,
        title="[bold]Traffic", title_style="bold cyan",
        border_style="rgb(60,100,160)",
    )
    traffic_table.add_column("Metric", style="dim", width=14)
    traffic_table.add_column("↓ Receive", style="bold green", justify="right")
    traffic_table.add_column("↑ Transmit", style="bold magenta", justify="right")

    traffic_table.add_row("Data", stats.bytes_in_human, stats.bytes_out_human)
    traffic_table.add_row("Packets", f"{stats.packets_in:,}", f"{stats.packets_out:,}")
    traffic_table.add_row("Errors", f"{stats.errors_in:,}", f"{stats.errors_out:,}")

    last_upd = stats.last_update.strftime("%H:%M:%S") if stats.last_update else "—"
    traffic_table.add_row("Last Update", last_upd, "")

    layout["right"].update(Panel(traffic_table, border_style="rgb(60,100,160)"))

    # ── Footer ──
    footer_text = Text("  Press Ctrl+C to disconnect and exit  ", style="dim italic")
    layout["footer"].update(Panel(footer_text, style="dim"))

    return layout


def run_dashboard(runner: OpenConnectRunner):
    """Run the live-updating TUI dashboard."""
    console = Console()

    with Live(render_dashboard(runner.stats), console=console, refresh_per_second=2) as live:
        try:
            while runner.process and runner.process.poll() is None:
                live.update(render_dashboard(runner.stats))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            live.update(render_dashboard(runner.stats))


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