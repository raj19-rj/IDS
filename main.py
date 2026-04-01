from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ids.detector import IntrusionDetector
from ids.models import Event
from ids.sniffer import sniff_events


def load_events(path: Path) -> list[Event]:
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
                print(
                    f"Skipping invalid record at line {line_number}: {exc}",
                    file=sys.stderr,
                )
    return events


def print_alerts(alerts) -> None:
    if not alerts:
        print("No alerts detected.")
        return

    print("Alerts:")
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.rule_name}: "
            f"{alert.description} "
            f"(src={alert.src_ip}, time={alert.timestamp.isoformat()})"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Starter intrusion detection system")
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to JSONL events file for offline analysis",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live traffic using scapy",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for live capture",
    )
    parser.add_argument(
        "--packet-count",
        type=int,
        default=100,
        help="Maximum number of live packets to capture",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    detector = IntrusionDetector()

    if args.input:
        events = load_events(args.input)
        alerts = detector.process_events(events)
        print_alerts(alerts)
        return 0

    if args.live:
        try:
            events = sniff_events(iface=args.interface, packet_count=args.packet_count)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        alerts = detector.process_events(events)
        print_alerts(alerts)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
