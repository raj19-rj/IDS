from __future__ import annotations

import unittest
from uuid import uuid4
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from ids.config import (
    DashboardConfig,
    DetectionConfig,
    IDSConfig,
    MonitoringConfig,
    ResponseConfig,
    StorageConfig,
)
from ids.detector import IntrusionDetector
from ids.ingest import EventLoader
from ids.monitor import IDSMonitor
from ids.responders import ResponderPipeline
from ids.storage import AlertStore


class MonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_monitor")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.sample_path = self.workspace / f"{uuid4().hex}.jsonl"
        self.sample_path.write_text(
            "\n".join(
                [
                    '{"timestamp":"2026-04-01T12:00:00","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","protocol":"TCP","src_port":5000,"dst_port":23,"size":120,"event_type":"packet","outcome":"unknown"}',
                    '{"timestamp":"2026-04-01T12:00:01","src_ip":"10.0.0.1","dst_ip":"10.0.0.3","protocol":"TCP","src_port":5001,"dst_port":23,"size":160,"event_type":"packet","outcome":"unknown"}',
                ]
            ),
            encoding="utf-8",
        )
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
            monitoring=MonitoringConfig(poll_interval_seconds=0),
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
        self.store = AlertStore(self.config.storage.database_path)
        self.monitor = IDSMonitor(
            config=self.config,
            detector=IntrusionDetector(self.config),
            store=self.store,
            loader=EventLoader(),
            responders=ResponderPipeline.from_config(self.config),
        )

    def test_replay_mode_generates_new_alerts_across_cycles(self) -> None:
        self.monitor.run(
            input_path=self.sample_path,
            input_format="jsonl",
            live=False,
            interface=None,
            packet_count=0,
            cycles=2,
            replay=True,
        )

        self.assertGreaterEqual(self.store.summary()["total_alerts"], 2)

    def test_replay_events_refreshes_timestamps(self) -> None:
        events = EventLoader().load_file(self.sample_path, "jsonl")

        replayed = self.monitor._replay_events(events)

        self.assertEqual(len(replayed), 2)
        self.assertGreater(replayed[0].timestamp, datetime(2026, 4, 1, 12, 0, 0))

    def test_live_capture_runtime_error_does_not_crash_monitor(self) -> None:
        with patch("ids.monitor.sniff_events", side_effect=RuntimeError("missing scapy")):
            self.monitor.run(
                input_path=None,
                input_format="jsonl",
                live=True,
                interface=None,
                packet_count=10,
                cycles=2,
                replay=False,
            )

        self.assertEqual(self.store.summary()["total_alerts"], 0)


if __name__ == "__main__":
    unittest.main()
