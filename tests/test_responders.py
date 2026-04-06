from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

from ids.config import (
    DashboardConfig,
    DetectionConfig,
    IDSConfig,
    MonitoringConfig,
    ResponseConfig,
    StorageConfig,
)
from ids.models import Alert
from ids.responders import ResponderPipeline


class ResponderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_responders")
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
            storage=StorageConfig(database_path=self.workspace / f"{uuid4().hex}.sqlite"),
            monitoring=MonitoringConfig(poll_interval_seconds=1),
            dashboard=DashboardConfig(
                username="admin",
                password_hash="x",
                password_salt="y",
                secret_key="z",
            ),
            response=ResponseConfig(
                auto_block_enabled=True,
                block_on_high_severity=True,
                block_command_mode="simulate",
                blocked_ips=set(),
            ),
        )

    def _build_alert(self, src_ip: str, severity: str = "HIGH") -> Alert:
        return Alert(
            timestamp=datetime(2026, 4, 1, 12, 0, 0),
            severity=severity,
            rule_name="Port Scan",
            description="scan",
            src_ip=src_ip,
            dst_ip="10.0.0.10",
            metadata={"x": "1"},
        )

    def test_invalid_ip_is_rejected(self) -> None:
        pipeline = ResponderPipeline.from_config(self.config)

        result = pipeline.handle([self._build_alert("1.2.3.4; rm -rf /")])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "invalid_ip")

    def test_simulated_command_uses_safe_argument_rendering(self) -> None:
        pipeline = ResponderPipeline.from_config(self.config)

        result = pipeline.handle([self._build_alert("1.2.3.4")])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "simulated")
        self.assertIn("1.2.3.4", result[0].detail)

    def test_real_mode_uses_argument_list(self) -> None:
        self.config.response.block_command_mode = "execute"
        pipeline = ResponderPipeline.from_config(self.config)

        with patch("ids.responders.platform.system", return_value="linux"), patch(
            "ids.responders.subprocess.run"
        ) as mocked_run:
            mocked_run.return_value = None
            result = pipeline.handle([self._build_alert("1.2.3.4")])

        self.assertEqual(result[0].status, "executed")
        call_args = mocked_run.call_args[0][0]
        self.assertIsInstance(call_args, list)
        self.assertIn("1.2.3.4", " ".join(call_args))


if __name__ == "__main__":
    unittest.main()
