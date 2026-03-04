# School VPN Connect Tool

A command-line tool that automates VPN login via browser-based SSO authentication, captures cookies, and connects using `openconnect` — with a live TUI dashboard showing uptime, traffic, and connection stats.

## How It Works

1. **Opens a real Chromium browser** to your school's VPN portal
2. **You log in normally** (SSO, MFA, etc. all work)
3. **Captures the auth cookie** once login succeeds
4. **Passes the cookie to `openconnect`** to establish the VPN tunnel
5. **Displays a live dashboard** with uptime, packet counts, data transferred, and errors

## Installation

```bash
# Install system dependencies
sudo apt install openconnect    # Debian/Ubuntu
# brew install openconnect      # macOS
# sudo dnf install openconnect  # Fedora

# Install Python dependencies
pip install playwright rich
playwright install chromium
```

## Usage

### Basic
```bash
sudo python3 vpn_connect.py --url https://vpn.yourschool.edu
```

### Specify cookie name
Different VPN vendors use different cookie names:
- **Cisco AnyConnect / ocserv**: `DSID`, `webvpn`, `webvpnc`
- **Palo Alto GlobalProtect**: `portal`, `PORTAL`
- **Pulse Secure / Ivanti**: `DSID`
- **F5 BIG-IP**: `MRHSession`

```bash
sudo python3 vpn_connect.py --url https://vpn.school.edu --cookie-name webvpn
```

### Different protocols
```bash
# GlobalProtect
sudo python3 vpn_connect.py --url https://vpn.school.edu --protocol gp

# Pulse Secure
sudo python3 vpn_connect.py --url https://vpn.school.edu --protocol pulse

# F5 BIG-IP
sudo python3 vpn_connect.py --url https://vpn.school.edu --protocol f5
```

### Debug: just dump cookies
```bash
python3 vpn_connect.py --url https://vpn.school.edu --dump-cookies
```

### Pass extra args to openconnect
```bash
sudo python3 vpn_connect.py --url https://vpn.school.edu \
    --extra-args --no-dtls --servercert pin-sha256:XXXX
```

## Dashboard

Once connected, the tool displays a live dashboard:

```
┌─ ◆ VPN Connect ──────────────────────────────────────────┐
│  ◆ VPN CONNECT   Connected (DTLS)   ⏱ 01:23:45           │
├──────────────────────────┬───────────────────────────────┤
│  Connection              │  Traffic                      │
│  Server   vpn.school.edu │  Metric      ↓ RX     ↑ TX    │
│  Local IP 10.0.12.34     │  Data     45.2 MB  12.1 MB    │
│  DNS      10.0.0.1       │  Packets  31,204   18,442     │
│  CSTP     AES-256-GCM    │  Errors   0        0          │
│  Uptime   01:23:45       │                               │
├──────────────────────────┴───────────────────────────────┤
│  Press Ctrl+C to disconnect and exit                     │
└──────────────────────────────────────────────────────────┘
```

## Tips

- **Root required**: `openconnect` needs root to create the tun device. Run with `sudo`.
- **Browser doesn't close?** If auto-detection misses your cookie, close the browser manually — all cookies will be captured.
- **Duo/MFA**: Works fine — the browser is a real Chromium instance, so push notifications, TOTP, etc. all work.
- **Custom server**: If the login URL differs from the VPN server, use `--server` to specify the actual VPN endpoint.