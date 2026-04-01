from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from ids.models import Alert, Event


class IntrusionDetector:
    def __init__(self) -> None:
        self.suspicious_ports = {23, 445, 3389, 4444}
        self.port_scan_threshold = 10
        self.failed_login_threshold = 5
        self.traffic_burst_threshold = 20
        self.window = timedelta(minutes=1)

    def process_events(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        ordered_events = sorted(events, key=lambda event: event.timestamp)

        alerts.extend(self._detect_port_scans(ordered_events))
        alerts.extend(self._detect_failed_logins(ordered_events))
        alerts.extend(self._detect_suspicious_ports(ordered_events))
        alerts.extend(self._detect_traffic_bursts(ordered_events))

        return sorted(alerts, key=lambda alert: alert.timestamp)

    def _detect_port_scans(self, events: list[Event]) -> list[Alert]:
        grouped: dict[str, list[Event]] = defaultdict(list)
        alerts: list[Alert] = []

        for event in events:
            grouped[event.src_ip].append(event)

        for src_ip, src_events in grouped.items():
            for index, event in enumerate(src_events):
                window_events = [
                    candidate
                    for candidate in src_events[index:]
                    if candidate.timestamp - event.timestamp <= self.window
                ]
                unique_ports = {candidate.dst_port for candidate in window_events}
                if len(unique_ports) >= self.port_scan_threshold:
                    alerts.append(
                        Alert(
                            timestamp=event.timestamp,
                            severity="HIGH",
                            rule_name="Port Scan",
                            description=(
                                f"Source touched {len(unique_ports)} unique destination "
                                f"ports within one minute"
                            ),
                            src_ip=src_ip,
                        )
                    )
                    break

        return alerts

    def _detect_failed_logins(self, events: list[Event]) -> list[Alert]:
        failed_login_counts: Counter[str] = Counter()
        latest_event: dict[str, Event] = {}

        for event in events:
            if event.event_type == "login_failed":
                failed_login_counts[event.src_ip] += 1
                latest_event[event.src_ip] = event

        alerts: list[Alert] = []
        for src_ip, count in failed_login_counts.items():
            if count >= self.failed_login_threshold:
                alerts.append(
                    Alert(
                        timestamp=latest_event[src_ip].timestamp,
                        severity="HIGH",
                        rule_name="Brute Force Login",
                        description=f"{count} failed login events recorded",
                        src_ip=src_ip,
                    )
                )

        return alerts

    def _detect_suspicious_ports(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        seen_pairs: set[tuple[str, int]] = set()

        for event in events:
            key = (event.src_ip, event.dst_port)
            if event.dst_port in self.suspicious_ports and key not in seen_pairs:
                seen_pairs.add(key)
                alerts.append(
                    Alert(
                        timestamp=event.timestamp,
                        severity="MEDIUM",
                        rule_name="Suspicious Port Access",
                        description=f"Traffic sent to suspicious port {event.dst_port}",
                        src_ip=event.src_ip,
                    )
                )

        return alerts

    def _detect_traffic_bursts(self, events: list[Event]) -> list[Alert]:
        grouped: dict[str, list[Event]] = defaultdict(list)
        alerts: list[Alert] = []

        for event in events:
            grouped[event.src_ip].append(event)

        for src_ip, src_events in grouped.items():
            for index, event in enumerate(src_events):
                count = 0
                for candidate in src_events[index:]:
                    if candidate.timestamp - event.timestamp <= self.window:
                        count += 1
                    else:
                        break

                if count >= self.traffic_burst_threshold:
                    alerts.append(
                        Alert(
                            timestamp=event.timestamp,
                            severity="MEDIUM",
                            rule_name="Traffic Burst",
                            description=(
                                f"{count} events observed from one source within one minute"
                            ),
                            src_ip=src_ip,
                        )
                    )
                    break

        return alerts
