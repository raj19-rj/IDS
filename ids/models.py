from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256


def parse_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue

    return datetime.fromisoformat(normalized)


@dataclass(slots=True)
class Event:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    size: int
    event_type: str = "packet"
    outcome: str = "unknown"

    @classmethod
    def from_dict(cls, payload: dict) -> "Event":
        return cls(
            timestamp=parse_timestamp(str(payload["timestamp"])),
            src_ip=str(payload["src_ip"]),
            dst_ip=str(payload["dst_ip"]),
            protocol=str(payload.get("protocol", "TCP")).upper(),
            src_port=int(payload.get("src_port", 0)),
            dst_port=int(payload.get("dst_port", 0)),
            size=int(payload.get("size", 0)),
            event_type=str(payload.get("event_type", "packet")).lower(),
            outcome=str(payload.get("outcome", "unknown")).lower(),
        )


@dataclass(slots=True)
class Alert:
    timestamp: datetime
    severity: str
    rule_name: str
    description: str
    src_ip: str
    dst_ip: str
    metadata: dict[str, str]

    @property
    def fingerprint(self) -> str:
        base = "|".join(
            [
                self.timestamp.isoformat(),
                self.severity,
                self.rule_name,
                self.description,
                self.src_ip,
                self.dst_ip,
            ]
        )
        return sha256(base.encode("utf-8")).hexdigest()
