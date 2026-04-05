from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from ids.models import Event, parse_timestamp


class EventLoader:
    def load_file(self, path: Path, file_format: str) -> list[Event]:
        if file_format == "jsonl":
            return self.load_jsonl(path)
        if file_format == "csv":
            return self.load_csv(path)
        if file_format == "suricata-eve":
            return self.load_suricata_eve(path)
        if file_format == "zeek-conn":
            return self.load_zeek_conn(path)
        if file_format == "windows-firewall":
            return self.load_windows_firewall(path)
        raise ValueError(f"Unsupported format: {file_format}")

    def load_jsonl(self, path: Path) -> list[Event]:
        events: list[Event] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    events.append(Event.from_dict(payload))
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(f"Invalid JSONL record at line {line_number}: {exc}") from exc
        return events

    def load_csv(self, path: Path) -> list[Event]:
        events: list[Event] = []
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row_number, row in enumerate(reader, start=2):
                try:
                    events.append(Event.from_dict(row))
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(f"Invalid CSV record at line {row_number}: {exc}") from exc
        return events

    def parse_lines(self, lines: list[str], file_format: str) -> list[Event]:
        if file_format not in {"jsonl", "suricata-eve"}:
            raise ValueError(
                "Incremental line parsing currently supports jsonl and suricata-eve only"
            )

        events: list[Event] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if file_format == "jsonl":
                events.append(Event.from_dict(payload))
            else:
                events.extend(self._parse_suricata_record(payload))
        return events

    def load_suricata_eve(self, path: Path) -> list[Event]:
        events: list[Event] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    events.extend(self._parse_suricata_record(payload))
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(
                        f"Invalid Suricata eve record at line {line_number}: {exc}"
                    ) from exc
        return events

    def load_zeek_conn(self, path: Path) -> list[Event]:
        fields: list[str] = []
        separator = "\t"
        events: list[Event] = []

        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#separator"):
                    separator_value = line.split(" ", 1)[1]
                    separator = bytes(separator_value, "utf-8").decode("unicode_escape")
                    continue
                if line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not fields:
                    raise ValueError("Zeek conn log is missing a #fields header")

                values = raw_line.rstrip("\n").split(separator)
                record = dict(zip(fields, values))
                try:
                    events.append(self._parse_zeek_conn_record(record))
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(
                        f"Invalid Zeek conn record at line {line_number}: {exc}"
                    ) from exc
        return events

    def load_windows_firewall(self, path: Path) -> list[Event]:
        fields: list[str] = []
        events: list[Event] = []

        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:") :].strip().split()
                    continue
                if line.startswith("#"):
                    continue
                if not fields:
                    raise ValueError("Windows firewall log is missing a #Fields header")

                values = line.split()
                record = dict(zip(fields, values))
                try:
                    events.append(self._parse_windows_firewall_record(record))
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(
                        f"Invalid Windows firewall record at line {line_number}: {exc}"
                    ) from exc
        return events

    def _parse_suricata_record(self, payload: dict) -> list[Event]:
        event_type = str(payload.get("event_type", "packet")).lower()
        if event_type not in {"alert", "flow"}:
            return []

        timestamp = parse_timestamp(str(payload["timestamp"]))
        src_ip = str(payload.get("src_ip", "0.0.0.0"))
        dst_ip = str(payload.get("dest_ip", "0.0.0.0"))
        src_port = int(payload.get("src_port", 0) or 0)
        dst_port = int(payload.get("dest_port", 0) or 0)
        protocol = str(payload.get("proto", "TCP")).upper()
        size = int(payload.get("flow", {}).get("bytes_toserver", 0) or 0)
        if not size:
            size = int(payload.get("length", 0) or 0)

        return [
            Event(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                size=size,
                event_type="packet",
                outcome="unknown",
            )
        ]

    def _parse_zeek_conn_record(self, record: dict[str, str]) -> Event:
        timestamp = datetime.fromtimestamp(float(record["ts"]))
        return Event(
            timestamp=timestamp,
            src_ip=str(record.get("id.orig_h", "0.0.0.0")),
            dst_ip=str(record.get("id.resp_h", "0.0.0.0")),
            protocol=str(record.get("proto", "tcp")).upper(),
            src_port=int(float(record.get("id.orig_p", 0) or 0)),
            dst_port=int(float(record.get("id.resp_p", 0) or 0)),
            size=int(float(record.get("orig_bytes", 0) or 0))
            + int(float(record.get("resp_bytes", 0) or 0)),
            event_type="packet",
            outcome="unknown",
        )

    def _parse_windows_firewall_record(self, record: dict[str, str]) -> Event:
        timestamp = parse_timestamp(f"{record['date']} {record['time']}")
        return Event(
            timestamp=timestamp,
            src_ip=str(record.get("src-ip", "0.0.0.0")),
            dst_ip=str(record.get("dst-ip", "0.0.0.0")),
            protocol=str(record.get("protocol", "TCP")).upper(),
            src_port=int(record.get("src-port", 0) or 0),
            dst_port=int(record.get("dst-port", 0) or 0),
            size=int(record.get("size", 0) or 0),
            event_type="packet",
            outcome=str(record.get("action", "unknown")).lower(),
        )
