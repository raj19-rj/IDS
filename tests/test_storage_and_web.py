from __future__ import annotations

import unittest
import json
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ids.config import (
    DashboardConfig,
    DetectionConfig,
    IDSConfig,
    MonitoringConfig,
    ResponseConfig,
    StorageConfig,
)
from ids.models import Alert
from ids.storage import AlertStore
from ids.web import create_server


class StorageAndWebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_storage")
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
                password_hash="4e7a94a1b8ac55d23c40cd3ce4c4d0e670add71b012de74799ae71c5715de547",
                password_salt="ids-demo-salt",
                secret_key="change-this-secret-key",
            ),
            response=ResponseConfig(
                auto_block_enabled=False,
                block_on_high_severity=True,
                block_command_mode="simulate",
                blocked_ips=set(),
            ),
        )
        self.store = AlertStore(self.config.storage.database_path)

    def test_store_deduplicates_alerts(self) -> None:
        alert = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="1.2.3.4",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )

        saved_first = self.store.save_alerts([alert])
        saved_second = self.store.save_alerts([alert])

        self.assertEqual(saved_first, 1)
        self.assertEqual(saved_second, 0)
        self.assertEqual(self.store.summary()["total_alerts"], 1)

    def test_dashboard_server_starts(self) -> None:
        server = create_server(self.config, self.store, host="127.0.0.1", port=0)
        self.assertIsNotNone(server)
        server.server_close()

    def test_export_alerts_to_json(self) -> None:
        alert = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="1.2.3.4",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )
        self.store.save_alerts([alert])
        export_path = self.workspace / f"{uuid4().hex}.json"

        exported_count = self.store.export_alerts(export_path, "json")

        self.assertEqual(exported_count, 1)
        exported_rows = json.loads(export_path.read_text(encoding="utf-8"))
        self.assertEqual(len(exported_rows), 1)
        self.assertEqual(exported_rows[0]["src_ip"], "1.2.3.4")
        self.assertEqual(exported_rows[0]["metadata"]["x"], "1")

    def test_list_alerts_can_filter_by_severity_and_source(self) -> None:
        first = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="1.2.3.4",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )
        second = Alert(
            timestamp=datetime(2026, 4, 1, 12, 5, 0),
            severity="MEDIUM",
            rule_name="Suspicious Port Access",
            description="port",
            src_ip="5.6.7.8",
            dst_ip="10.0.0.20",
            metadata={"port": "23"},
        )
        self.store.save_alerts([first, second])

        filtered = self.store.list_alerts(severity="HIGH", src_ip="1.2.3.4")

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["rule_name"], "Port Scan")

    def test_list_alerts_supports_offset_and_count(self) -> None:
        alerts = [
            Alert(
                timestamp=datetime(2026, 4, 1, 12, index, 0),
                severity="HIGH" if index % 2 == 0 else "MEDIUM",
                rule_name="Port Scan",
                description=f"scan {index}",
                src_ip=f"1.2.3.{index}",
                dst_ip="10.0.0.10",
                metadata={"x": str(index)},
            )
            for index in range(4)
        ]
        self.store.save_alerts(alerts)

        paged = self.store.list_alerts(limit=2, offset=1)
        count = self.store.count_alerts(rule_name="Port Scan")

        self.assertEqual(len(paged), 2)
        self.assertEqual(count, 4)

    def test_store_can_lookup_alert_and_distinct_values(self) -> None:
        alert = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="1.2.3.4",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )
        self.store.save_alerts([alert])

        found = self.store.get_alert(alert.fingerprint)
        values = self.store.distinct_values()

        self.assertIsNotNone(found)
        self.assertEqual(found["rule_name"], "Port Scan")
        self.assertIn("HIGH", values["severities"])
        self.assertIn("1.2.3.4", values["source_ips"])
        self.assertIn("Port Scan", values["rules"])

    def test_live_snapshot_reports_recent_activity(self) -> None:
        now = datetime.now()
        alerts = [
            Alert(
                timestamp=now - timedelta(minutes=2),
                severity="HIGH",
                rule_name="Port Scan",
                description="scan",
                src_ip="1.2.3.4",
                dst_ip="10.0.0.10",
                metadata={"x": "1"},
            ),
            Alert(
                timestamp=now - timedelta(seconds=30),
                severity="MEDIUM",
                rule_name="Traffic Burst",
                description="burst",
                src_ip="1.2.3.4",
                dst_ip="10.0.0.20",
                metadata={"bytes": "2000"},
            ),
        ]
        self.store.save_alerts(alerts)

        snapshot = self.store.live_snapshot(window_minutes=15)

        self.assertTrue(snapshot["is_live"])
        self.assertEqual(snapshot["recent_alert_count"], 2)
        self.assertEqual(snapshot["high_recent_count"], 1)
        self.assertEqual(snapshot["medium_recent_count"], 1)
        self.assertEqual(snapshot["source_tracker"][0]["src_ip"], "1.2.3.4")
        self.assertGreaterEqual(len(snapshot["timeline"]), 1)

    def test_live_snapshot_handles_mixed_timezone_timestamps(self) -> None:
        aware_alert = Alert(
            timestamp=datetime.now(timezone.utc) - timedelta(seconds=20),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="9.9.9.9",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )
        naive_alert = Alert(
            timestamp=datetime.now() - timedelta(seconds=10),
            severity="MEDIUM",
            rule_name="Traffic Burst",
            description="burst",
            src_ip="8.8.8.8",
            dst_ip="10.0.0.20",
            metadata={"bytes": "2000"},
        )
        self.store.save_alerts([aware_alert, naive_alert])

        snapshot = self.store.live_snapshot(window_minutes=15)

        self.assertEqual(snapshot["recent_alert_count"], 2)
        self.assertIsNotNone(snapshot["last_alert_at"])

    def test_runtime_state_can_be_updated(self) -> None:
        self.store.update_runtime_state(
            monitor_running=True,
            mode="replay",
            warning="demo warning",
            last_cycle=3,
            last_message="Cycle 3 complete.",
        )

        runtime = self.store.runtime_state()

        self.assertTrue(runtime["monitor_running"])
        self.assertEqual(runtime["mode"], "replay")
        self.assertEqual(runtime["warning"], "demo warning")
        self.assertEqual(runtime["last_cycle"], 3)

    def test_list_alerts_orders_mixed_timezone_timestamps_correctly(self) -> None:
        aware_alert = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 30, tzinfo=timezone.utc),
            severity="HIGH",
            rule_name="Port Scan",
            description="scan",
            src_ip="9.9.9.9",
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )
        naive_alert = Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity="MEDIUM",
            rule_name="Traffic Burst",
            description="burst",
            src_ip="8.8.8.8",
            dst_ip="10.0.0.20",
            metadata={"bytes": "2000"},
        )
        self.store.save_alerts([naive_alert, aware_alert])

        alerts = self.store.list_alerts()

        self.assertEqual(alerts[0]["rule_name"], "Port Scan")


if __name__ == "__main__":
    unittest.main()
