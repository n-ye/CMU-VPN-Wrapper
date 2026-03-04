from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta



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