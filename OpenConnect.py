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
        self._tun_device: Optional[str] = None  # Track the actual tun interface name
        self._log_lines: list[str] = []          # Keep recent log lines for debugging

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
        """Parse openconnect stdout/stderr for connection info.

        Handles output formats from multiple protocols:
        - AnyConnect: "Got address 10.x.x.x", "CSTP connected", "DTLS connected"
        - GlobalProtect: "Connected as 10.x.x.x, using SSL", "ESP session established"
        - Pulse/F5: Similar to AnyConnect with minor variations
        """
        for line in self.process.stdout:
            line = line.strip()
            if self._stop_event.is_set():
                break

            # Store recent lines for debugging
            self._log_lines.append(line)
            if len(self._log_lines) > 200:
                self._log_lines = self._log_lines[-100:]

            with self._lock:
                self._parse_line(line)

        # Process ended
        with self._lock:
            if self.stats.status != "Disconnected":
                self.stats.status = "Disconnected"

    def _parse_line(self, line: str):
        """Parse a single line of openconnect output. Must be called with self._lock held."""

        # ── Connection status ──────────────────────────────────────────

        # GlobalProtect: "Connected as 10.5.201.132, using SSL"
        # GlobalProtect: "Connected as 10.5.201.132, using SSL, with ESP disabled"
        m = re.search(r"Connected as ([\d.]+)", line)
        if m:
            self.stats.local_ip = m.group(1)
            self.stats.status = "Connected"
            if not self.stats.connected_at:
                self.stats.connected_at = datetime.now()

        # AnyConnect: "Connected to HTTPS on vpn.school.edu with ciphersuite..."
        if "Connected to HTTPS" in line or ("Connected" in line and "SSL" in line):
            if self.stats.status not in ("Connected", "Connected (DTLS)", "Connected (ESP)"):
                self.stats.status = "Connected"
                if not self.stats.connected_at:
                    self.stats.connected_at = datetime.now()

        # ESP/DTLS tunnel established (upgrade from SSL)
        if "ESP session established" in line or "ESP tunnel connected" in line:
            self.stats.status = "Connected (ESP)"
            if not self.stats.connected_at:
                self.stats.connected_at = datetime.now()

        if "DTLS connected" in line or "DTLS session resumed" in line:
            self.stats.status = "Connected (DTLS)"
            if not self.stats.connected_at:
                self.stats.connected_at = datetime.now()

        # ── IP address extraction ──────────────────────────────────────

        # AnyConnect/Pulse: "Got address 10.x.x.x" or "Got IPv4 10.x.x.x"
        m = re.search(r"Got (?:address|IPv4)\s+([\d.]+)", line)
        if m:
            self.stats.local_ip = m.group(1)

        # ── DNS ────────────────────────────────────────────────────────

        # "Got DNS 10.0.0.1" or "Got DNS server 10.0.0.1"
        m = re.search(r"Got DNS\s+(?:server\s+)?([\d.]+)", line)
        if m:
            if m.group(1) not in self.stats.dns_servers:
                self.stats.dns_servers.append(m.group(1))

        # ── Cipher info ────────────────────────────────────────────────

        # AnyConnect: "CSTP connected. DPD 30, Keepalive 20, cipher AES-256-GCM"
        m = re.search(r"CSTP connected.*cipher\s+(.+?)(?:\s*$)", line)
        if m:
            self.stats.cstp_cipher = m.group(1).strip()

        # AnyConnect: "DTLS connected. DPD 30, cipher AES-256-GCM"
        m = re.search(r"DTLS connected.*cipher\s+(.+?)(?:\s*$)", line)
        if m:
            self.stats.dtls_cipher = m.group(1).strip()

        # GlobalProtect: "ESP encryption type AES-128-CBC (RFC3602)"
        m = re.search(r"ESP encryption type\s+(.+?)(?:\s*$)", line)
        if m:
            self.stats.cstp_cipher = f"ESP: {m.group(1).strip()}"

        # GlobalProtect: "ESP authentication type HMAC-SHA-1-96 (RFC2404)"
        m = re.search(r"ESP authentication type\s+(.+?)(?:\s*$)", line)
        if m:
            self.stats.dtls_cipher = f"Auth: {m.group(1).strip()}"

        # SSL cipher from negotiation: "Negotiated cipher suite: TLS_AES_256_GCM_SHA384"
        m = re.search(r"(?:Negotiated|SSL)\s+cipher\s+(?:suite:\s+)?(.+?)(?:\s*$)", line)
        if m and not self.stats.cstp_cipher:
            self.stats.cstp_cipher = m.group(1).strip()

        # ── TUN device name ────────────────────────────────────────────

        # "Using tun0 as tun device" or "Opened tun device tun0"
        # "Set up tun device: tun0"
        m = re.search(r"(?:Using|Opened|Set up)\s+(?:tun device:?\s+)?(\w*tun\d+)", line)
        if m:
            self._tun_device = m.group(1)

        # Also catch: "Connected tun0 as 10.x.x.x...", "utun5", etc.
        m = re.search(r"((?:u?tun)\d+)", line)
        if m and not self._tun_device:
            self._tun_device = m.group(1)

        # ── Disconnect detection ───────────────────────────────────────

        if any(s in line for s in ["Disconnected", "connection closed", "Session terminated"]):
            if "retry" not in line.lower() and "reconnect" not in line.lower():
                self.stats.status = "Disconnected"

        if "Failed" in line and "ESP" not in line:
            # ESP failures are non-fatal (falls back to SSL)
            if "retry" not in line.lower():
                self.stats.status = "Disconnected"

    def _poll_interface_stats(self):
        """Poll network interface stats for the tun device.

        Cross-platform:
        - macOS: `netstat -ibI <device>` for byte/packet counters
        - Linux: /proc/net/dev or `ip -s link show`
        """
        time.sleep(3)

        is_macos = sys.platform == "darwin"

        while not self._stop_event.is_set():
            time.sleep(2)
            try:
                device = self._tun_device

                # If we don't know the device yet, try to discover it
                if not device:
                    device = self._discover_tun_device(is_macos)
                    if device:
                        self._tun_device = device
                    else:
                        continue

                if is_macos:
                    self._read_netstat_stats(device)
                else:
                    if not self._read_proc_net_dev():
                        self._read_ip_stats(device)

            except Exception:
                pass

    def _discover_tun_device(self, is_macos: bool) -> Optional[str]:
        """Find the active tun/utun device used by the VPN."""
        try:
            if is_macos:
                result = subprocess.run(
                    ["ifconfig", "-l"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    return None

                utuns = [i for i in result.stdout.strip().split() if i.startswith("utun")]

                # If we already know the local IP from openconnect output, find the
                # utun that has that exact IP
                known_ip = self.stats.local_ip if self.stats.local_ip else None

                for iface in utuns:
                    detail = subprocess.run(
                        ["ifconfig", iface],
                        capture_output=True, text=True, timeout=5,
                    )
                    output = detail.stdout

                    # Skip interfaces with no IPv4
                    if "inet " not in output:
                        continue

                    # If we know the VPN IP, match it exactly
                    if known_ip and known_ip in output:
                        return iface

                    # Otherwise match common VPN private ranges
                    m = re.search(r"inet\s+([\d.]+)", output)
                    if m:
                        ip = m.group(1)
                        if (ip.startswith("10.") or
                            ip.startswith("172.") or
                            ip.startswith("192.168.")):
                            return iface

                # Last resort: highest-numbered utun
                if utuns:
                    return utuns[-1]

            else:
                # Linux: check /proc/net/dev
                try:
                    with open("/proc/net/dev") as f:
                        for line in f:
                            iface = line.split(":")[0].strip()
                            if re.match(r"^u?tun\d+$", iface):
                                return iface
                except FileNotFoundError:
                    pass

                for dev in ["tun0", "tun1"]:
                    result = subprocess.run(
                        ["ip", "link", "show", dev],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        return dev

        except Exception:
            pass
        return None

    def _read_netstat_stats(self, device: str) -> bool:
        """macOS: parse `netstat -ibI <device>` for byte and packet counters."""
        try:
            result = subprocess.run(
                ["netstat", "-ibI", device],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return False

            for line in result.stdout.strip().split("\n"):
                # Only parse the <Link#N> row — it has stable column layout
                if "<Link#" not in line:
                    continue

                parts = line.split()
                # Expected: Name Mtu <Link#N> Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                # That's 10 fields (Address is empty so it's skipped by split)
                if len(parts) < 10:
                    continue

                try:
                    # Parse from right: Coll Obytes Oerrs Opkts Ibytes Ierrs Ipkts
                    coll    = int(parts[-1])
                    obytes  = int(parts[-2])
                    oerrs   = int(parts[-3])
                    opkts   = int(parts[-4])
                    ibytes  = int(parts[-5])
                    ierrs   = int(parts[-6])
                    ipkts   = int(parts[-7])

                    with self._lock:
                        self.stats.bytes_in = ibytes
                        self.stats.packets_in = ipkts
                        self.stats.errors_in = ierrs
                        self.stats.bytes_out = obytes
                        self.stats.packets_out = opkts
                        self.stats.errors_out = oerrs
                        self.stats.last_update = datetime.now()
                    return True

                except (ValueError, IndexError):
                    continue

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return False

    def _read_proc_net_dev(self) -> bool:
        """Linux: parse /proc/net/dev for tun interface stats."""
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    line = line.strip()
                    iface = line.split(":")[0].strip() if ":" in line else ""
                    if not iface:
                        continue

                    is_target = False
                    if self._tun_device and iface == self._tun_device:
                        is_target = True
                    elif re.match(r"^u?tun\d+$", iface):
                        is_target = True
                        if not self._tun_device:
                            self._tun_device = iface

                    if not is_target:
                        continue

                    parts = line.split(":")[1].split()
                    if len(parts) >= 16:
                        with self._lock:
                            self.stats.bytes_in = int(parts[0])
                            self.stats.packets_in = int(parts[1])
                            self.stats.errors_in = int(parts[2])
                            self.stats.bytes_out = int(parts[8])
                            self.stats.packets_out = int(parts[9])
                            self.stats.errors_out = int(parts[10])
                            self.stats.last_update = datetime.now()
                        return True

        except (FileNotFoundError, PermissionError):
            pass
        return False

    def _read_ip_stats(self, device: str) -> bool:
        """Linux: read stats via `ip -s link show <device>`."""
        try:
            result = subprocess.run(
                ["ip", "-s", "link", "show", device],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return False

            lines = result.stdout.split("\n")
            rx_bytes = rx_packets = rx_errors = 0
            tx_bytes = tx_packets = tx_errors = 0

            i = 0
            while i < len(lines):
                stripped = lines[i].strip()
                if stripped.startswith("RX:") and i + 1 < len(lines):
                    parts = lines[i + 1].strip().split()
                    if len(parts) >= 3:
                        rx_bytes, rx_packets, rx_errors = int(parts[0]), int(parts[1]), int(parts[2])
                elif stripped.startswith("TX:") and i + 1 < len(lines):
                    parts = lines[i + 1].strip().split()
                    if len(parts) >= 3:
                        tx_bytes, tx_packets, tx_errors = int(parts[0]), int(parts[1]), int(parts[2])
                i += 1

            with self._lock:
                self.stats.bytes_in = rx_bytes
                self.stats.packets_in = rx_packets
                self.stats.errors_in = rx_errors
                self.stats.bytes_out = tx_bytes
                self.stats.packets_out = tx_packets
                self.stats.errors_out = tx_errors
                self.stats.last_update = datetime.now()
            return True

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False