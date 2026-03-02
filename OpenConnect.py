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