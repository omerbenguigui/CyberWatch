"""Small SQLite repository with parameterized queries and explicit transactions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from app.models import Alert, AlertCreate, AlertStatus, LogEvent, LogEventCreate, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT,
    destination_port INTEGER,
    username TEXT,
    message TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_ip, event_type, timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    source_ip TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_source ON alerts(rule_id, source_ip, created_at);
"""


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Database:
    """Persistence layer. Each operation owns its connection for thread safety."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._schema_lock = Lock()
        self._initialized = False
        self._transaction_connection: sqlite3.Connection | None = None

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        if self._transaction_connection is not None:
            yield self._transaction_connection
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[Database]:
        """Yield a separate, single-threaded repository sharing one atomic transaction."""
        self.initialize()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            repository = Database(self.path)
            repository._initialized = True
            repository._transaction_connection = connection
            try:
                yield repository
            finally:
                repository._transaction_connection = None

    def initialize(self) -> None:
        with self._schema_lock:
            if self._initialized:
                return
            with self.connection() as connection:
                connection.executescript(SCHEMA)
            self._initialized = True

    def insert_event(self, event: LogEventCreate) -> LogEvent:
        self.initialize()
        values = (
            _iso(event.timestamp),
            event.event_type.value,
            event.source_ip,
            event.destination_ip,
            event.destination_port,
            event.username,
            event.message,
            json.dumps(event.metadata, separators=(",", ":"), sort_keys=True),
        )
        with self.connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    timestamp, event_type, source_ip, destination_ip,
                    destination_port, username, message, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            event_id = int(cursor.lastrowid or 0)
        return LogEvent(id=event_id, **event.model_dump())

    def list_events(
        self,
        *,
        limit: int = 100,
        event_type: str | None = None,
        source_ip: str | None = None,
        since: datetime | None = None,
    ) -> list[LogEvent]:
        self.initialize()
        since_value = _iso(since) if since else None
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE (? IS NULL OR event_type = ?)
                  AND (? IS NULL OR source_ip = ?)
                  AND (? IS NULL OR timestamp >= ?)
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (
                    event_type,
                    event_type,
                    source_ip,
                    source_ip,
                    since_value,
                    since_value,
                    limit,
                ),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def create_alert(self, alert: AlertCreate) -> Alert:
        self.initialize()
        with self.connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO alerts (
                    created_at, rule_id, title, description, severity,
                    status, source_ip, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(alert.created_at),
                    alert.rule_id,
                    alert.title,
                    alert.description,
                    alert.severity.value,
                    AlertStatus.OPEN.value,
                    alert.source_ip,
                    json.dumps(alert.evidence, separators=(",", ":"), sort_keys=True),
                ),
            )
            alert_id = int(cursor.lastrowid or 0)
        return Alert(id=alert_id, status=AlertStatus.OPEN, **alert.model_dump())

    def has_recent_alert(self, rule_id: str, source_ip: str, since: datetime) -> bool:
        self.initialize()
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM alerts
                WHERE rule_id = ? AND source_ip = ? AND created_at >= ?
                LIMIT 1
                """,
                (rule_id, source_ip, _iso(since)),
            ).fetchone()
        return row is not None

    def list_alerts(
        self,
        *,
        limit: int = 100,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
    ) -> list[Alert]:
        self.initialize()
        status_value = status.value if status else None
        severity_value = severity.value if severity else None
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM alerts
                WHERE (? IS NULL OR status = ?)
                  AND (? IS NULL OR severity = ?)
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (
                    status_value,
                    status_value,
                    severity_value,
                    severity_value,
                    limit,
                ),
            ).fetchall()
        return [self._alert_from_row(row) for row in rows]

    def acknowledge_alert(self, alert_id: int) -> Alert | None:
        self.initialize()
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (AlertStatus.ACKNOWLEDGED.value, alert_id),
            )
            if cursor.rowcount == 0:
                return None
            row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert_from_row(row)

    def dashboard_summary(self) -> dict[str, Any]:
        self.initialize()
        with self.connection() as connection:
            total_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            open_alerts = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
            ).fetchone()[0]
            critical_alerts = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status = 'open'"
            ).fetchone()[0]
            unique_sources = connection.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM events"
            ).fetchone()[0]
            event_rows = connection.execute(
                "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
            ).fetchall()
            alert_rows = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            ).fetchall()
        return {
            "total_events": total_events,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "unique_sources": unique_sources,
            "events_by_type": {row["event_type"]: row["count"] for row in event_rows},
            "alerts_by_severity": {row["severity"]: row["count"] for row in alert_rows},
        }

    def count_distinct_ports(self, source_ip: str, since: datetime) -> int:
        self.initialize()
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT COUNT(DISTINCT destination_port)
                FROM events
                WHERE source_ip = ? AND event_type = 'network_connection'
                  AND destination_port IS NOT NULL AND timestamp >= ?
                """,
                (source_ip, _iso(since)),
            ).fetchone()
        return int(row[0])

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> LogEvent:
        return LogEvent(
            id=row["id"],
            timestamp=_parse_datetime(row["timestamp"]),
            event_type=row["event_type"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            destination_port=row["destination_port"],
            username=row["username"],
            message=row["message"],
            metadata=json.loads(row["metadata"]),
        )

    @staticmethod
    def _alert_from_row(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            created_at=_parse_datetime(row["created_at"]),
            rule_id=row["rule_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            status=row["status"],
            source_ip=row["source_ip"],
            evidence=json.loads(row["evidence"]),
        )
