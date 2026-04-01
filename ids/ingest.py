from __future__ import annotations

import csv
import json
from pathlib import Path

from ids.models import Event


class EventLoader:
    def load_file(self, path: Path, file_format: str) -> list[Event]:
        if file_format == "jsonl":
            return self.load_jsonl(path)
        if file_format == "csv":
            return self.load_csv(path)
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
        if file_format != "jsonl":
            raise ValueError("Incremental line parsing currently supports jsonl only")

        events: list[Event] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            events.append(Event.from_dict(json.loads(line)))
        return events
