from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ids.models import Alert


class AlertStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.database_path.exists():
            self.database_path.write_text("", encoding="utf-8")

    def save_alerts(self, alerts: list[Alert]) -> int:
        existing = {record["fingerprint"] for record in self._read_all()}
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

    def list_alerts(self, limit: int = 100) -> list[dict[str, str]]:
        rows = self._read_all()
        rows.sort(key=lambda row: row["timestamp"], reverse=True)
        return rows[:limit]

    def summary(self) -> dict[str, object]:
        rows = self._read_all()
        severity_counts = Counter(row["severity"] for row in rows)
        source_counts = Counter(row["src_ip"] for row in rows)
        top_sources = [
            {"src_ip": src_ip, "count": count}
            for src_ip, count in source_counts.most_common(5)
        ]
        return {
            "total_alerts": len(rows),
            "severity_counts": dict(severity_counts),
            "top_sources": top_sources,
        }

    def _read_all(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        with self.database_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows
