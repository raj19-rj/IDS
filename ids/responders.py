from __future__ import annotations

import ipaddress
import platform
import subprocess
from dataclasses import dataclass

from ids.config import IDSConfig
from ids.models import Alert


@dataclass(slots=True)
class ResponseResult:
    action: str
    src_ip: str
    status: str
    detail: str


class ResponderPipeline:
    def __init__(self, config: IDSConfig) -> None:
        self.config = config
        self.results: list[ResponseResult] = []

    @classmethod
    def from_config(cls, config: IDSConfig) -> "ResponderPipeline":
        return cls(config)

    def handle(self, alerts: list[Alert]) -> list[ResponseResult]:
        self.results = []
        if not self.config.response.auto_block_enabled:
            return self.results

        for alert in alerts:
            if self.config.response.block_on_high_severity and alert.severity != "HIGH":
                continue
            if alert.src_ip in self.config.response.blocked_ips:
                continue
            self.results.append(self._block_ip(alert.src_ip))
        return self.results

    def _block_ip(self, src_ip: str) -> ResponseResult:
        normalized_ip = self._normalize_ip(src_ip)
        if normalized_ip is None:
            return ResponseResult(
                action="block_ip",
                src_ip=src_ip,
                status="invalid_ip",
                detail="Source IP is not a valid IPv4/IPv6 address",
            )

        mode = self.config.response.block_command_mode
        if mode == "simulate":
            return ResponseResult(
                action="block_ip",
                src_ip=normalized_ip,
                status="simulated",
                detail=self._build_block_command(normalized_ip),
            )

        command = self._build_command_parts(normalized_ip)
        if not command:
            return ResponseResult(
                action="block_ip",
                src_ip=normalized_ip,
                status="unsupported",
                detail="No firewall command available for this operating system",
            )

        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except Exception as exc:  # noqa: BLE001
            return ResponseResult(
                action="block_ip",
                src_ip=normalized_ip,
                status="failed",
                detail=str(exc),
            )

        return ResponseResult(
            action="block_ip",
            src_ip=normalized_ip,
            status="executed",
            detail="Firewall rule added",
        )

    def _normalize_ip(self, src_ip: str) -> str | None:
        try:
            return str(ipaddress.ip_address(src_ip))
        except ValueError:
            return None

    def _build_block_command(self, src_ip: str) -> str:
        command = self._build_command_parts(src_ip)
        if not command:
            return "unsupported"
        return " ".join(command)

    def _build_command_parts(self, src_ip: str) -> list[str]:
        system = platform.system().lower()
        if system == "windows":
            return [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=IDS Block {src_ip}",
                "dir=in",
                "action=block",
                f"remoteip={src_ip}",
            ]
        if system == "linux":
            return ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
        return []
