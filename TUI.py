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
from Models import VPNStats

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