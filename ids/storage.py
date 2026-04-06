from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock

from ids.models import Alert


class AlertStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._lock = RLock()
        self._runtime_state: dict[str, object] = {
            "monitor_running": False,
            "mode": "idle",
            "warning": "",
            "last_cycle": 0,
            "last_message": "Monitor not started.",
            "updated_at": None,
        }
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.database_path.exists():
            self.database_path.write_text("", encoding="utf-8")

    def save_alerts(self, alerts: list[Alert]) -> int:
        with self._lock:
            existing = {record["fingerprint"] for record in self._read_all_unlocked()}
            saved = 0
            with self.database_path.open("a", encoding="utf-8") as handle:
                for alert in alerts:
                    if alert.fingerprint in existing:
                        continue
                    handle.write(
                        json.dumps(
                            {
                                "fingerprint": alert.fingerprint,
                                "timestamp": alert.timestamp.isoformat(),
                                "severity": alert.severity,
                                "rule_name": alert.rule_name,
                                "description": alert.description,
                                "src_ip": alert.src_ip,
                                "dst_ip": alert.dst_ip,
                                "metadata_json": json.dumps(alert.metadata, sort_keys=True),
                            }
                        )
                        + "\n"
                    )
                    existing.add(alert.fingerprint)
                    saved += 1
            return saved

    def list_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        src_ip: str | None = None,
        rule_name: str | None = None,
        search: str | None = None,
        sort_by: str = "timestamp",
        sort_dir: str = "desc",
    ) -> list[dict[str, object]]:
        rows = self._filter_rows(
            self._read_all(),
            severity=severity,
            src_ip=src_ip,
            rule_name=rule_name,
            search=search,
        )
        reverse = sort_dir.lower() != "asc"
        sort_key_map = {
            "timestamp": lambda row: self._parse_timestamp(str(row["timestamp"])),
            "severity": lambda row: str(row["severity"]),
            "rule_name": lambda row: str(row["rule_name"]).lower(),
            "src_ip": lambda row: str(row["src_ip"]).lower(),
            "dst_ip": lambda row: str(row["dst_ip"]).lower(),
        }
        rows.sort(key=sort_key_map.get(sort_by, sort_key_map["timestamp"]), reverse=reverse)
        return rows[offset : offset + limit]

    def summary(self) -> dict[str, object]:
        rows = self._read_all()
        severity_counts = Counter(row["severity"] for row in rows)
        source_counts = Counter(row["src_ip"] for row in rows)
        rule_counts = Counter(row["rule_name"] for row in rows)
        top_sources = [
            {"src_ip": src_ip, "count": count}
            for src_ip, count in source_counts.most_common(5)
        ]
        return {
            "total_alerts": len(rows),
            "severity_counts": dict(severity_counts),
            "top_sources": top_sources,
            "top_rules": [
                {"rule_name": rule_name, "count": count}
                for rule_name, count in rule_counts.most_common(5)
            ],
        }

    def get_alert(self, fingerprint: str) -> dict[str, object] | None:
        for row in self._read_all():
            if row["fingerprint"] == fingerprint:
                return row
        return None

    def count_alerts(
        self,
        severity: str | None = None,
        src_ip: str | None = None,
        rule_name: str | None = None,
        search: str | None = None,
    ) -> int:
        rows = self._filter_rows(
            self._read_all(),
            severity=severity,
            src_ip=src_ip,
            rule_name=rule_name,
            search=search,
        )
        return len(rows)

    def distinct_values(self) -> dict[str, list[str]]:
        rows = self._read_all()
        severities = sorted({str(row["severity"]) for row in rows})
        source_ips = sorted({str(row["src_ip"]) for row in rows})
        rules = sorted({str(row["rule_name"]) for row in rows})
        return {
            "severities": severities,
            "source_ips": source_ips,
            "rules": rules,
        }

    def update_runtime_state(self, **fields: object) -> None:
        with self._lock:
            self._runtime_state.update(fields)
            self._runtime_state["updated_at"] = datetime.now(timezone.utc).isoformat()

    def runtime_state(self) -> dict[str, object]:
        with self._lock:
            return dict(self._runtime_state)

    def live_snapshot(
        self,
        *,
        window_minutes: int = 15,
        feed_limit: int = 8,
        tracker_limit: int = 6,
        timeline_buckets: int = 10,
    ) -> dict[str, object]:
        rows = self._read_all()
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(minutes=window_minutes)
        parsed_rows = [
            (self._parse_timestamp(str(row["timestamp"])), row)
            for row in rows
        ]
        parsed_rows.sort(key=lambda item: item[0], reverse=True)
        recent_rows = [row for timestamp, row in parsed_rows if timestamp >= recent_cutoff]

        high_recent = [row for row in recent_rows if row["severity"] == "HIGH"]
        medium_recent = [row for row in recent_rows if row["severity"] == "MEDIUM"]
        top_recent_sources = Counter(str(row["src_ip"]) for row in recent_rows)
        top_recent_rules = Counter(str(row["rule_name"]) for row in recent_rows)

        source_tracker: list[dict[str, object]] = []
        tracker_index: dict[str, dict[str, object]] = {}
        for timestamp, row in parsed_rows:
            if timestamp < recent_cutoff:
                continue
            src_ip = str(row["src_ip"])
            if src_ip not in tracker_index:
                tracker_index[src_ip] = {
                    "src_ip": src_ip,
                    "count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "last_seen": row["timestamp"],
                    "latest_rule": row["rule_name"],
                    "destinations": set(),
                }
            entry = tracker_index[src_ip]
            entry["count"] = int(entry["count"]) + 1
            if row["severity"] == "HIGH":
                entry["high_count"] = int(entry["high_count"]) + 1
            if row["severity"] == "MEDIUM":
                entry["medium_count"] = int(entry["medium_count"]) + 1
            cast_destinations = entry["destinations"]
            assert isinstance(cast_destinations, set)
            cast_destinations.add(str(row["dst_ip"]))

        for entry in sorted(
            tracker_index.values(),
            key=lambda item: (int(item["high_count"]), int(item["count"])),
            reverse=True,
        )[:tracker_limit]:
            destinations = entry.pop("destinations")
            source_tracker.append(
                {
                    **entry,
                    "destinations": sorted(str(value) for value in destinations)[:3],
                }
            )

        bucket_count = max(1, timeline_buckets)
        bucket_span_seconds = max(60, int(window_minutes * 60 / bucket_count))
        timeline: list[dict[str, object]] = []
        for index in range(bucket_count):
            bucket_end = now - timedelta(seconds=bucket_span_seconds * (bucket_count - index - 1))
            bucket_start = bucket_end - timedelta(seconds=bucket_span_seconds)
            bucket_rows = [
                row
                for timestamp, row in parsed_rows
                if bucket_start < timestamp <= bucket_end
            ]
            timeline.append(
                {
                    "label": bucket_end.strftime("%H:%M"),
                    "count": len(bucket_rows),
                    "high": sum(1 for row in bucket_rows if row["severity"] == "HIGH"),
                    "medium": sum(1 for row in bucket_rows if row["severity"] == "MEDIUM"),
                }
            )

        last_alert_at = parsed_rows[0][1]["timestamp"] if parsed_rows else None
        return {
            "window_minutes": window_minutes,
            "recent_alert_count": len(recent_rows),
            "high_recent_count": len(high_recent),
            "medium_recent_count": len(medium_recent),
            "alerts_per_minute": round(len(recent_rows) / max(window_minutes, 1), 2),
            "threat_score": min(100, len(high_recent) * 18 + len(medium_recent) * 9),
            "is_live": bool(parsed_rows and (now - parsed_rows[0][0]).total_seconds() <= 60),
            "last_alert_at": last_alert_at,
            "top_recent_sources": [
                {"src_ip": src_ip, "count": count}
                for src_ip, count in top_recent_sources.most_common(5)
            ],
            "top_recent_rules": [
                {"rule_name": rule_name, "count": count}
                for rule_name, count in top_recent_rules.most_common(5)
            ],
            "feed": recent_rows[:feed_limit],
            "source_tracker": source_tracker,
            "timeline": timeline,
        }

    def export_alerts(self, output_path: Path, export_format: str) -> int:
        rows = self._read_all()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if export_format == "json":
            output_rows = [
                {
                    "fingerprint": row["fingerprint"],
                    "timestamp": row["timestamp"],
                    "severity": row["severity"],
                    "rule_name": row["rule_name"],
                    "description": row["description"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "metadata": row["metadata"],
                }
                for row in rows
            ]
            output_path.write_text(json.dumps(output_rows, indent=2), encoding="utf-8")
            return len(rows)

        if export_format == "csv":
            with output_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "timestamp",
                        "severity",
                        "rule_name",
                        "description",
                        "src_ip",
                        "dst_ip",
                        "metadata_json",
                        "fingerprint",
                    ],
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "timestamp": row["timestamp"],
                            "severity": row["severity"],
                            "rule_name": row["rule_name"],
                            "description": row["description"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "metadata_json": json.dumps(row["metadata"], sort_keys=True),
                            "fingerprint": row["fingerprint"],
                        }
                        for row in rows
                    ]
                )
            return len(rows)

        raise ValueError(f"Unsupported export format: {export_format}")

    def _read_all(self) -> list[dict[str, object]]:
        with self._lock:
            return self._read_all_unlocked()

    def _read_all_unlocked(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        with self.database_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    row["metadata"] = json.loads(row.pop("metadata_json"))
                except json.JSONDecodeError:
                    continue
                rows.append(row)
        return rows

    def _parse_timestamp(self, value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _filter_rows(
        self,
        rows: list[dict[str, object]],
        severity: str | None,
        src_ip: str | None,
        rule_name: str | None,
        search: str | None,
    ) -> list[dict[str, object]]:
        if severity:
            rows = [row for row in rows if row["severity"] == severity]
        if src_ip:
            rows = [row for row in rows if row["src_ip"] == src_ip]
        if rule_name:
            rows = [row for row in rows if row["rule_name"] == rule_name]
        if search:
            query = search.lower()
            rows = [
                row
                for row in rows
                if query in row["description"].lower()
                or query in row["src_ip"].lower()
                or query in row["dst_ip"].lower()
                or query in row["rule_name"].lower()
                or any(query in str(value).lower() for value in row["metadata"].values())
            ]
        return rows
