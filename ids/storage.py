from __future__ import annotations

import csv
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

    def list_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        src_ip: str | None = None,
    ) -> list[dict[str, object]]:
        rows = self._read_all()
        if severity:
            rows = [row for row in rows if row["severity"] == severity]
        if src_ip:
            rows = [row for row in rows if row["src_ip"] == src_ip]
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
        rows: list[dict[str, object]] = []
        with self.database_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                row["metadata"] = json.loads(row.pop("metadata_json"))
                rows.append(row)
        return rows
