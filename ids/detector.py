from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta

from ids.config import IDSConfig
from ids.models import Alert, Event


class IntrusionDetector:
    def __init__(self, config: IDSConfig) -> None:
        self.config = config
        self.window = timedelta(seconds=config.detection.window_seconds)

    def process_events(self, events: list[Event]) -> list[Alert]:
        ordered_events = sorted(
            [
                event
                for event in events
                if event.src_ip not in self.config.detection.allowlisted_ips
            ],
            key=lambda event: event.timestamp,
        )
        alerts: list[Alert] = []
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
                window_events: deque[Event] = deque(src_events[index:index])
                window_events.append(event)
                unique_ports = {event.dst_port}
                for candidate in src_events[index + 1 :]:
                    if candidate.timestamp - event.timestamp > self.window:
                        break
                    window_events.append(candidate)
                    unique_ports.add(candidate.dst_port)
                if len(unique_ports) >= self.config.detection.port_scan_threshold:
                    alerts.append(
                        Alert(
                            timestamp=event.timestamp,
                            severity="HIGH",
                            rule_name="Port Scan",
                            description=(
                                f"Source touched {len(unique_ports)} unique destination "
                                f"ports in {self.config.detection.window_seconds} seconds"
                            ),
                            src_ip=src_ip,
                            dst_ip=event.dst_ip,
                            metadata={"unique_ports": str(len(unique_ports))},
                        )
                    )
                    break

        return alerts

    def _detect_failed_logins(self, events: list[Event]) -> list[Alert]:
        grouped: dict[str, list[Event]] = defaultdict(list)
        alerts: list[Alert] = []

        for event in events:
            if event.event_type == "login_failed" or (
                event.event_type == "auth" and event.outcome == "failed"
            ):
                grouped[event.src_ip].append(event)

        for src_ip, src_events in grouped.items():
            window_events: deque[Event] = deque()
            for event in src_events:
                window_events.append(event)
                while window_events and event.timestamp - window_events[0].timestamp > self.window:
                    window_events.popleft()
                if len(window_events) >= self.config.detection.failed_login_threshold:
                    alerts.append(
                        Alert(
                            timestamp=event.timestamp,
                            severity="HIGH",
                            rule_name="Brute Force Login",
                            description=(
                                f"{len(window_events)} failed login events observed in "
                                f"{self.config.detection.window_seconds} seconds"
                            ),
                            src_ip=src_ip,
                            dst_ip=event.dst_ip,
                            metadata={"failed_logins": str(len(window_events))},
                        )
                    )
                    break

        return alerts

    def _detect_suspicious_ports(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        seen_pairs: set[tuple[str, int]] = set()

        for event in events:
            key = (event.src_ip, event.dst_port)
            if (
                event.dst_port in self.config.detection.suspicious_ports
                and key not in seen_pairs
            ):
                seen_pairs.add(key)
                alerts.append(
                    Alert(
                        timestamp=event.timestamp,
                        severity="MEDIUM",
                        rule_name="Suspicious Port Access",
                        description=f"Traffic sent to suspicious port {event.dst_port}",
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        metadata={"port": str(event.dst_port)},
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
                window_events: deque[Event] = deque()
                for candidate in src_events[index:]:
                    if candidate.timestamp - event.timestamp > self.window:
                        break
                    window_events.append(candidate)

                if len(window_events) >= self.config.detection.traffic_burst_threshold:
                    byte_count = sum(candidate.size for candidate in window_events)
                    alerts.append(
                        Alert(
                            timestamp=event.timestamp,
                            severity="MEDIUM",
                            rule_name="Traffic Burst",
                            description=(
                                f"{len(window_events)} events and {byte_count} bytes observed in "
                                f"{self.config.detection.window_seconds} seconds"
                            ),
                            src_ip=src_ip,
                            dst_ip=event.dst_ip,
                            metadata={
                                "event_count": str(len(window_events)),
                                "bytes": str(byte_count),
                            },
                        )
                    )
                    break

        return alerts

    def summarize_events(self, events: list[Event]) -> dict[str, int]:
        protocol_counts = Counter(event.protocol for event in events)
        return dict(protocol_counts)
