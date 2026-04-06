from __future__ import annotations

from datetime import datetime
import time
from pathlib import Path

from ids.config import IDSConfig
from ids.detector import IntrusionDetector
from ids.ingest import EventLoader
from ids.models import Event
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
        replay: bool = False,
    ) -> None:
        print("Starting IDS monitor. Press Ctrl+C to stop.")
        completed_cycles = 0
        file_offset = 0
        live_capture_available = live
        mode = "replay" if replay else "live" if live else "tail"
        self.store.update_runtime_state(
            monitor_running=True,
            mode=mode,
            warning="",
            last_cycle=0,
            last_message="Monitor starting.",
        )

        while cycles is None or completed_cycles < cycles:
            alerts = []

            if input_path is not None:
                if replay:
                    events = self.loader.load_file(input_path, input_format)
                    alerts.extend(self.detector.process_events(self._replay_events(events)))
                elif input_format == "jsonl":
                    new_lines, file_offset = self._read_new_lines(input_path, file_offset)
                    if new_lines:
                        events = self.loader.parse_lines(new_lines, input_format)
                        alerts.extend(self.detector.process_events(events))
                else:
                    events = self.loader.load_file(input_path, input_format)
                    alerts.extend(self.detector.process_events(events))

            if live_capture_available:
                try:
                    events = sniff_events(iface=interface, packet_count=packet_count)
                except RuntimeError as exc:
                    live_capture_available = False
                    print(f"Live capture disabled: {exc}")
                    self.store.update_runtime_state(
                        warning=str(exc),
                        last_message="Live capture disabled. Monitor is continuing without packet sniffing.",
                    )
                    events = []
                alerts.extend(self.detector.process_events(events))

            if alerts:
                stored_count = self.store.save_alerts(alerts)
                self.responders.handle(alerts)
                message = (
                    f"Cycle {completed_cycles + 1}: detected {len(alerts)} alert(s), "
                    f"stored {stored_count} new alert(s)."
                )
                print(message)
                self.store.update_runtime_state(
                    last_cycle=completed_cycles + 1,
                    last_message=message,
                )
            else:
                message = f"Cycle {completed_cycles + 1}: no alerts."
                print(message)
                self.store.update_runtime_state(
                    last_cycle=completed_cycles + 1,
                    last_message=message,
                )

            completed_cycles += 1
            if cycles is None or completed_cycles < cycles:
                time.sleep(self.config.monitoring.poll_interval_seconds)

        self.store.update_runtime_state(
            monitor_running=False,
            last_message=f"Monitor finished after {completed_cycles} cycle(s).",
        )

    def _read_new_lines(self, path: Path, offset: int) -> tuple[list[str], int]:
        if not path.exists():
            return [], offset

        with path.open("r", encoding="utf-8") as handle:
            handle.seek(offset)
            lines = handle.readlines()
            new_offset = handle.tell()

        return lines, new_offset

    def _replay_events(self, events: list[Event]) -> list[Event]:
        if not events:
            return []

        ordered = sorted(events, key=lambda event: event.timestamp)
        base_time = ordered[0].timestamp
        replay_start = datetime.now()
        replayed: list[Event] = []
        for event in ordered:
            replayed.append(
                Event(
                    timestamp=replay_start + (event.timestamp - base_time),
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    protocol=event.protocol,
                    src_port=event.src_port,
                    dst_port=event.dst_port,
                    size=event.size,
                    event_type=event.event_type,
                    outcome=event.outcome,
                )
            )
        return replayed
