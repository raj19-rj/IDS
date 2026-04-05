from __future__ import annotations

import unittest
from pathlib import Path
from uuid import uuid4

from ids.ingest import EventLoader


class WindowsIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_windows_ingest")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.loader = EventLoader()

    def test_loads_windows_event_log_json(self) -> None:
        path = self.workspace / f"{uuid4().hex}.jsonl"
        path.write_text(
            '{"TimeCreated":"2026-04-06T09:00:00","EventID":4625,"IpAddress":"10.0.0.50","Computer":"WORKSTATION-1"}\n',
            encoding="utf-8",
        )

        events = self.loader.load_file(path, "windows-events-json")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "auth")
        self.assertEqual(events[0].outcome, "failed")

    def test_loads_sysmon_json(self) -> None:
        path = self.workspace / f"{uuid4().hex}.jsonl"
        path.write_text(
            '{"UtcTime":"2026-04-06T09:05:00","EventID":3,"SourceIp":"10.0.0.60","DestinationIp":"10.0.0.10","SourcePort":52000,"DestinationPort":3389,"Protocol":"tcp"}\n',
            encoding="utf-8",
        )

        events = self.loader.load_file(path, "sysmon-json")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dst_port, 3389)
        self.assertEqual(events[0].protocol, "TCP")


if __name__ == "__main__":
    unittest.main()
