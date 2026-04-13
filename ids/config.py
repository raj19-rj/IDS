from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from ids.security import hash_password


@dataclass(slots=True)
class DetectionConfig:
    window_seconds: int
    suspicious_ports: set[int]
    port_scan_threshold: int
    failed_login_threshold: int
    traffic_burst_threshold: int
    allowlisted_ips: set[str]


@dataclass(slots=True)
class StorageConfig:
    database_path: Path


@dataclass(slots=True)
class MonitoringConfig:
    poll_interval_seconds: int


@dataclass(slots=True)
class DashboardConfig:
    username: str
    password_hash: str
    password_salt: str
    secret_key: str


@dataclass(slots=True)
class ResponseConfig:
    auto_block_enabled: bool
    block_on_high_severity: bool
    block_command_mode: str
    blocked_ips: set[str]


@dataclass(slots=True)
class IDSConfig:
    detection: DetectionConfig
    storage: StorageConfig
    monitoring: MonitoringConfig
    dashboard: DashboardConfig
    response: ResponseConfig


DEFAULT_CONFIG = {
    "detection": {
        "window_seconds": 60,
        "suspicious_ports": [23, 445, 3389, 4444],
        "port_scan_threshold": 10,
        "failed_login_threshold": 5,
        "traffic_burst_threshold": 20,
        "allowlisted_ips": ["127.0.0.1", "::1"],
    },
    "storage": {
        "database_path": "data/alerts.sqlite",
    },
    "monitoring": {
        "poll_interval_seconds": 5,
    },
    "dashboard": {
        "username": "",
        "password_hash": "",
        "password_salt": "change-this-password-salt",
        "secret_key": "change-this-secret-key",
    },
    "response": {
        "auto_block_enabled": False,
        "block_on_high_severity": True,
        "block_command_mode": "simulate",
        "blocked_ips": [],
    },
}

def ensure_config_file(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")


def _env_or_default(name: str, fallback: str) -> str:
    return os.getenv(name, fallback)


def _build_dashboard_config(raw_dashboard: dict) -> DashboardConfig:
    username = _env_or_default("IDS_DASHBOARD_USERNAME", str(raw_dashboard["username"]))
    password_salt = _env_or_default(
        "IDS_DASHBOARD_PASSWORD_SALT",
        str(raw_dashboard["password_salt"]),
    )
    password_hash = _env_or_default(
        "IDS_DASHBOARD_PASSWORD_HASH",
        str(raw_dashboard["password_hash"]),
    )
    password_plain = os.getenv("IDS_DASHBOARD_PASSWORD")
    if password_plain:
        password_hash = hash_password(password_plain, password_salt)

    secret_key = _env_or_default("IDS_SECRET_KEY", str(raw_dashboard["secret_key"]))
    if secret_key == "change-this-secret-key":
        secret_key = secrets.token_hex(32)

    return DashboardConfig(
        username=username,
        password_hash=password_hash,
        password_salt=password_salt,
        secret_key=secret_key,
    )


def load_config(path: Path) -> IDSConfig:
    ensure_config_file(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return IDSConfig(
        detection=DetectionConfig(
            window_seconds=int(raw["detection"]["window_seconds"]),
            suspicious_ports={int(port) for port in raw["detection"]["suspicious_ports"]},
            port_scan_threshold=int(raw["detection"]["port_scan_threshold"]),
            failed_login_threshold=int(raw["detection"]["failed_login_threshold"]),
            traffic_burst_threshold=int(raw["detection"]["traffic_burst_threshold"]),
            allowlisted_ips=set(raw["detection"].get("allowlisted_ips", [])),
        ),
        storage=StorageConfig(database_path=Path(raw["storage"]["database_path"])),
        monitoring=MonitoringConfig(
            poll_interval_seconds=int(raw["monitoring"]["poll_interval_seconds"])
        ),
        dashboard=_build_dashboard_config(raw["dashboard"]),
        response=ResponseConfig(
            auto_block_enabled=bool(raw["response"]["auto_block_enabled"]),
            block_on_high_severity=bool(raw["response"]["block_on_high_severity"]),
            block_command_mode=str(raw["response"]["block_command_mode"]),
            blocked_ips=set(raw["response"].get("blocked_ips", [])),
        ),
    )
