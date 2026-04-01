from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


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

    @classmethod
    def from_dict(cls, payload: dict) -> "Event":
        return cls(
            timestamp=datetime.fromisoformat(payload["timestamp"]),
            src_ip=str(payload["src_ip"]),
            dst_ip=str(payload["dst_ip"]),
            protocol=str(payload.get("protocol", "TCP")).upper(),
            src_port=int(payload.get("src_port", 0)),
            dst_port=int(payload.get("dst_port", 0)),
            size=int(payload.get("size", 0)),
            event_type=str(payload.get("event_type", "packet")),
        )


@dataclass(slots=True)
class Alert:
    timestamp: datetime
    severity: str
    rule_name: str
    description: str
    src_ip: str
