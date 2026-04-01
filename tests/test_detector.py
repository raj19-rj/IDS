from __future__ import annotations

import unittest
from uuid import uuid4
from datetime import datetime, timedelta
from pathlib import Path

from ids.config import (
    DashboardConfig,
    DetectionConfig,
    IDSConfig,
    MonitoringConfig,
    ResponseConfig,
    StorageConfig,
)
from ids.detector import IntrusionDetector
from ids.models import Event


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_detector")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.config = IDSConfig(
            detection=DetectionConfig(
                window_seconds=60,
                suspicious_ports={23, 445, 3389, 4444},
                port_scan_threshold=10,
                failed_login_threshold=5,
                traffic_burst_threshold=20,
                allowlisted_ips={"127.0.0.1", "::1"},
            ),
            storage=StorageConfig(database_path=self.workspace / f"{uuid4().hex}.jsonl"),
            monitoring=MonitoringConfig(poll_interval_seconds=1),
            dashboard=DashboardConfig(
                username="admin",
                password_hash="x",
                password_salt="y",
                secret_key="z",
            ),
            response=ResponseConfig(
                auto_block_enabled=False,
                block_on_high_severity=True,
                block_command_mode="simulate",
                blocked_ips=set(),
            ),
        )
        self.detector = IntrusionDetector(self.config)

    def test_detects_bruteforce_and_port_scan(self) -> None:
        base_time = datetime(2026, 4, 1, 12, 0, 0)
        events = [
            Event(
                timestamp=base_time + timedelta(seconds=index * 5),
                src_ip="10.0.0.5",
                dst_ip="10.0.0.10",
                protocol="TCP",
                src_port=5000 + index,
                dst_port=22,
                size=100,
                event_type="login_failed",
                outcome="failed",
            )
            for index in range(5)
        ]
        events.extend(
            Event(
                timestamp=base_time + timedelta(seconds=index),
                src_ip="10.0.0.8",
                dst_ip="10.0.0.20",
                protocol="TCP",
                src_port=6000 + index,
                dst_port=20 + index,
                size=80,
                event_type="packet",
                outcome="unknown",
            )
            for index in range(10)
        )

        alerts = self.detector.process_events(events)
        rule_names = {alert.rule_name for alert in alerts}

        self.assertIn("Brute Force Login", rule_names)
        self.assertIn("Port Scan", rule_names)

    def test_allowlisted_ip_is_ignored(self) -> None:
        base_time = datetime(2026, 4, 1, 12, 0, 0)
        events = [
            Event(
                timestamp=base_time + timedelta(seconds=index),
                src_ip="127.0.0.1",
                dst_ip="10.0.0.20",
                protocol="TCP",
                src_port=6000 + index,
                dst_port=20 + index,
                size=80,
                event_type="packet",
                outcome="unknown",
            )
            for index in range(10)
        ]

        alerts = self.detector.process_events(events)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
