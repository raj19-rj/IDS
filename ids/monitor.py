from __future__ import annotations

import time
from pathlib import Path

from ids.config import IDSConfig
from ids.detector import IntrusionDetector
from ids.ingest import EventLoader
from ids.responders import ResponderPipeline
from ids.sniffer import sniff_events
from ids.storage import AlertStore


class IDSMonitor:
    def __init__(
        self,
        config: IDSConfig,
        detector: IntrusionDetector,
        store: AlertStore,
        loader: EventLoader,
        responders: ResponderPipeline,
    ) -> None:
        self.config = config
        self.detector = detector
        self.store = store
        self.loader = loader
        self.responders = responders

    def run(
        self,
        input_path: Path | None,
        input_format: str,
        live: bool,
        interface: str | None,
        packet_count: int,
        cycles: int | None,
    ) -> None:
        print("Starting IDS monitor. Press Ctrl+C to stop.")
        completed_cycles = 0
        file_offset = 0

        while cycles is None or completed_cycles < cycles:
            alerts = []

            if input_path is not None:
                if input_format == "jsonl":
                    new_lines, file_offset = self._read_new_lines(input_path, file_offset)
                    if new_lines:
                        events = self.loader.parse_lines(new_lines, input_format)
                        alerts.extend(self.detector.process_events(events))
                else:
                    events = self.loader.load_file(input_path, input_format)
                    alerts.extend(self.detector.process_events(events))

            if live:
                events = sniff_events(iface=interface, packet_count=packet_count)
                alerts.extend(self.detector.process_events(events))

            if alerts:
                stored_count = self.store.save_alerts(alerts)
                self.responders.handle(alerts)
                print(
                    f"Cycle {completed_cycles + 1}: detected {len(alerts)} alert(s), "
                    f"stored {stored_count} new alert(s)."
                )
            else:
                print(f"Cycle {completed_cycles + 1}: no alerts.")

            completed_cycles += 1
            if cycles is None or completed_cycles < cycles:
                time.sleep(self.config.monitoring.poll_interval_seconds)

    def _read_new_lines(self, path: Path, offset: int) -> tuple[list[str], int]:
        if not path.exists():
            return [], offset

        with path.open("r", encoding="utf-8") as handle:
            handle.seek(offset)
            lines = handle.readlines()
            new_offset = handle.tell()

        return lines, new_offset
