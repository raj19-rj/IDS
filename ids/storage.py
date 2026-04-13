from __future__ import annotations

import csv
import hashlib
import json
import secrets
import sqlite3
import tempfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock

from ids.models import Alert

try:
    import bcrypt
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    bcrypt = None


class AlertStore:
    def __init__(self, database_path: Path) -> None:
        self._lock = RLock()
        self._runtime_state: dict[str, object] = {
            "monitor_running": False,
            "mode": "idle",
            "warning": "",
            "last_cycle": 0,
            "last_message": "Monitor not started.",
            "updated_at": None,
        }

        self._legacy_jsonl_path: Path | None = None
        resolved_path = database_path
        if database_path.suffix.lower() == ".jsonl":
            self._legacy_jsonl_path = database_path
            resolved_path = database_path.with_suffix(".sqlite")

        self.database_path = self._resolve_sqlite_path(resolved_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        with self._connection() as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            self._ensure_schema(connection)

        if self._legacy_jsonl_path is not None:
            self._migrate_legacy_jsonl(self._legacy_jsonl_path)

    def save_alerts(self, alerts: list[Alert]) -> int:
        if not alerts:
            return 0

        rows = [
            (
                alert.fingerprint,
                alert.timestamp.isoformat(),
                alert.severity,
                alert.rule_name,
                alert.description,
                alert.src_ip,
                alert.dst_ip,
                json.dumps(alert.metadata, sort_keys=True),
            )
            for alert in alerts
        ]

        with self._lock, self._connection() as connection:
            cursor = connection.executemany(
                """
                INSERT OR IGNORE INTO alerts (
                    fingerprint, timestamp, severity, rule_name,
                    description, src_ip, dst_ip, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            connection.commit()
            return cursor.rowcount if cursor.rowcount is not None else 0

    def create_user(self, username: str, password: str) -> bool:
        self._require_bcrypt()
        normalized_username = username.strip()
        if not normalized_username:
            raise ValueError("username cannot be empty")
        if not password:
            raise ValueError("password cannot be empty")

        password_salt = secrets.token_hex(16)
        salted_password = f"{password_salt}:{password}".encode("utf-8")
        password_hash = bcrypt.hashpw(salted_password, bcrypt.gensalt()).decode("utf-8")
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._lock, self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO users (username, password_hash, password_salt, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (normalized_username, password_hash, password_salt, created_at),
                )
                connection.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def verify_user_password(self, username: str, password: str) -> bool:
        self._require_bcrypt()
        normalized_username = username.strip()
        if not normalized_username or not password:
            return False

        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                SELECT password_hash, password_salt
                FROM users
                WHERE username = ?
                """,
                (normalized_username,),
            )
            row = cursor.fetchone()

        if row is None:
            return False

        stored_hash = str(row["password_hash"]).encode("utf-8")
        salted_password = f"{row['password_salt']}:{password}".encode("utf-8")
        return bcrypt.checkpw(salted_password, stored_hash)

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
        sort_column_map = {
            "timestamp": "timestamp",
            "severity": "severity",
            "rule_name": "rule_name",
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
        }
        safe_sort_column = sort_column_map.get(sort_by, "timestamp")
        safe_sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

        where_clause, params = self._build_where_clause(
            severity=severity,
            src_ip=src_ip,
            rule_name=rule_name,
            search=search,
        )

        query = f"""
            SELECT fingerprint, timestamp, severity, rule_name, description, src_ip, dst_ip, metadata_json
            FROM alerts
            {where_clause}
            ORDER BY {safe_sort_column} {safe_sort_dir}, fingerprint {safe_sort_dir}
            LIMIT ? OFFSET ?
        """

        with self._lock, self._connection() as connection:
            cursor = connection.execute(query, (*params, int(limit), int(offset)))
            return [self._row_to_dict(row) for row in cursor.fetchall()]

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
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                SELECT fingerprint, timestamp, severity, rule_name, description, src_ip, dst_ip, metadata_json
                FROM alerts
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None

    def count_alerts(
        self,
        severity: str | None = None,
        src_ip: str | None = None,
        rule_name: str | None = None,
        search: str | None = None,
    ) -> int:
        where_clause, params = self._build_where_clause(
            severity=severity,
            src_ip=src_ip,
            rule_name=rule_name,
            search=search,
        )
        query = f"SELECT COUNT(*) FROM alerts {where_clause}"
        with self._lock, self._connection() as connection:
            cursor = connection.execute(query, params)
            count_row = cursor.fetchone()
            return int(count_row[0]) if count_row else 0

    def distinct_values(self) -> dict[str, list[str]]:
        with self._lock, self._connection() as connection:
            severities = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT severity FROM alerts ORDER BY severity ASC"
                ).fetchall()
            ]
            source_ips = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT src_ip FROM alerts ORDER BY src_ip ASC"
                ).fetchall()
            ]
            rules = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name ASC"
                ).fetchall()
            ]
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

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> sqlite3.Connection:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _resolve_sqlite_path(self, desired_path: Path) -> Path:
        desired_path.parent.mkdir(parents=True, exist_ok=True)
        if self._can_open_sqlite(desired_path):
            return desired_path

        fallback_root = Path(tempfile.gettempdir()) / "ids-sqlite"
        fallback_root.mkdir(parents=True, exist_ok=True)
        fingerprint = hashlib.sha256(str(desired_path).encode("utf-8")).hexdigest()[:12]
        fallback_path = fallback_root / f"{desired_path.stem}-{fingerprint}.sqlite"
        return fallback_path

    def _can_open_sqlite(self, path: Path) -> bool:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE IF NOT EXISTS __ids_probe (x INTEGER)")
            connection.execute("INSERT INTO __ids_probe (x) VALUES (1)")
            connection.execute("DELETE FROM __ids_probe")
            connection.execute("DROP TABLE __ids_probe")
            connection.commit()
            return True
        except sqlite3.Error:
            return False
        finally:
            if connection is not None:
                connection.close()

    def _ensure_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                fingerprint TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                description TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name)")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")

    def _migrate_legacy_jsonl(self, legacy_path: Path) -> None:
        if not legacy_path.exists():
            return

        with self._lock, self._connection() as connection:
            current_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            if int(current_count) > 0:
                return

        legacy_rows: list[tuple[str, str, str, str, str, str, str, str]] = []
        with legacy_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                metadata_json = row.get("metadata_json", "{}")
                if isinstance(metadata_json, dict):
                    metadata_json = json.dumps(metadata_json, sort_keys=True)

                legacy_rows.append(
                    (
                        str(row.get("fingerprint", "")),
                        str(row.get("timestamp", "")),
                        str(row.get("severity", "LOW")),
                        str(row.get("rule_name", "Unknown Rule")),
                        str(row.get("description", "")),
                        str(row.get("src_ip", "0.0.0.0")),
                        str(row.get("dst_ip", "0.0.0.0")),
                        str(metadata_json),
                    )
                )

        if not legacy_rows:
            return

        with self._lock, self._connection() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO alerts (
                    fingerprint, timestamp, severity, rule_name,
                    description, src_ip, dst_ip, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                legacy_rows,
            )
            connection.commit()

    def _build_where_clause(
        self,
        *,
        severity: str | None,
        src_ip: str | None,
        rule_name: str | None,
        search: str | None,
    ) -> tuple[str, tuple[object, ...]]:
        clauses: list[str] = []
        params: list[object] = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if rule_name:
            clauses.append("rule_name = ?")
            params.append(rule_name)
        if search:
            like_query = f"%{search.lower()}%"
            clauses.append(
                "(" \
                "LOWER(description) LIKE ? OR " \
                "LOWER(src_ip) LIKE ? OR " \
                "LOWER(dst_ip) LIKE ? OR " \
                "LOWER(rule_name) LIKE ? OR " \
                "LOWER(metadata_json) LIKE ?" \
                ")"
            )
            params.extend([like_query, like_query, like_query, like_query, like_query])

        if not clauses:
            return "", tuple(params)
        return f"WHERE {' AND '.join(clauses)}", tuple(params)

    def _read_all(self) -> list[dict[str, object]]:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                SELECT fingerprint, timestamp, severity, rule_name, description, src_ip, dst_ip, metadata_json
                FROM alerts
                ORDER BY timestamp DESC, fingerprint DESC
                """
            )
            return [self._row_to_dict(row) for row in cursor.fetchall()]

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, object]:
        metadata_text = str(row["metadata_json"])
        try:
            metadata = json.loads(metadata_text)
            if not isinstance(metadata, dict):
                metadata = {"value": metadata}
        except json.JSONDecodeError:
            metadata = {}

        return {
            "fingerprint": str(row["fingerprint"]),
            "timestamp": str(row["timestamp"]),
            "severity": str(row["severity"]),
            "rule_name": str(row["rule_name"]),
            "description": str(row["description"]),
            "src_ip": str(row["src_ip"]),
            "dst_ip": str(row["dst_ip"]),
            "metadata": metadata,
        }

    def _parse_timestamp(self, value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _require_bcrypt(self) -> None:
        if bcrypt is None:
            raise RuntimeError(
                "bcrypt is required for user password operations. "
                "Install dependencies from requirements.txt."
            )
