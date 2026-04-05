from __future__ import annotations

import unittest
from pathlib import Path
from uuid import uuid4

from ids.ingest import EventLoader


class IngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path("tests/.tmp_ingest")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.loader = EventLoader()

    def test_loads_suricata_eve(self) -> None:
        path = self.workspace / f"{uuid4().hex}.json"
        path.write_text(
            '{"timestamp":"2026-04-05T10:00:00.000000+00:00","event_type":"alert","src_ip":"10.0.0.5","dest_ip":"10.0.0.10","src_port":50000,"dest_port":3389,"proto":"TCP","flow":{"bytes_toserver":420}}\n',
            encoding="utf-8",
        )

        events = self.loader.load_file(path, "suricata-eve")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dst_port, 3389)
        self.assertEqual(events[0].size, 420)

    def test_loads_zeek_conn(self) -> None:
        path = self.workspace / f"{uuid4().hex}.log"
        path.write_text(
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\n"
            "1712311200.0\t10.0.0.8\t50500\t10.0.0.20\t445\ttcp\t120\t40\n",
            encoding="utf-8",
        )

        events = self.loader.load_file(path, "zeek-conn")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].src_ip, "10.0.0.8")
        self.assertEqual(events[0].dst_port, 445)
        self.assertEqual(events[0].size, 160)

    def test_loads_windows_firewall_log(self) -> None:
        path = self.workspace / f"{uuid4().hex}.log"
        path.write_text(
            "#Version: 1.5\n"
            "#Fields: date time action protocol src-ip dst-ip src-port dst-port size\n"
            "2026-04-05 10:15:00 DROP TCP 10.0.0.9 10.0.0.30 53000 23 60\n",
            encoding="utf-8",
        )

        events = self.loader.load_file(path, "windows-firewall")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].outcome, "drop")
        self.assertEqual(events[0].dst_port, 23)


if __name__ == "__main__":
    unittest.main()
