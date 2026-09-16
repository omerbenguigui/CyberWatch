"""Generate safe, synthetic telemetry that demonstrates every detection rule."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.database import Database
from app.detection import DetectionEngine
from app.models import EventType, LogEventCreate


def generate_events(now: datetime | None = None) -> list[LogEventCreate]:
    current = now or datetime.now(UTC)
    events: list[LogEventCreate] = []

    for index in range(24):
        successful = index % 4 != 0
        events.append(
            LogEventCreate(
                timestamp=current - timedelta(minutes=45 - index),
                event_type=(EventType.LOGIN_SUCCESS if successful else EventType.FIREWALL_BLOCK),
                source_ip=f"10.0.0.{(index % 8) + 10}",
                destination_ip="10.0.0.5",
                destination_port=443,
                username=f"employee{index % 6 + 1}",
                message=(
                    "Routine corporate authentication" if successful else "Blocked inbound request"
                ),
            )
        )

    for index in range(5):
        events.append(
            LogEventCreate(
                timestamp=current - timedelta(minutes=4, seconds=30 - index * 5),
                event_type=EventType.LOGIN_FAILED,
                source_ip="203.0.113.42",
                destination_ip="10.0.0.5",
                destination_port=22,
                username="admin",
                message="Invalid password",
            )
        )

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
    for index, port in enumerate(ports):
        events.append(
            LogEventCreate(
                timestamp=current - timedelta(seconds=75 - index * 4),
                event_type=EventType.NETWORK_CONNECTION,
                source_ip="198.51.100.77",
                destination_ip="10.0.0.12",
                destination_port=port,
                message="Inbound connection attempt",
            )
        )

    events.append(
        LogEventCreate(
            timestamp=current - timedelta(seconds=20),
            event_type=EventType.PROCESS_START,
            source_ip="10.0.0.24",
            username="workstation-user",
            message="Suspicious PowerShell process",
            metadata={"command_line": "powershell.exe -EncodedCommand [redacted-demo-value]"},
        )
    )
    return sorted(events, key=lambda event: event.timestamp)


def seed_demo(database: Database) -> tuple[int, int]:
    """Populate an empty database once, atomically, including detection alerts."""
    with database.transaction() as repository:
        if repository.list_events(limit=1):
            return 0, 0
        detector = DetectionEngine(repository)
        alert_count = 0
        events = generate_events()
        for payload in events:
            event = repository.insert_event(payload)
            alert_count += len(detector.evaluate(event))
        return len(events), alert_count


def main() -> None:
    settings = Settings.from_environment()
    database = Database(settings.database_path)
    event_count, alert_count = seed_demo(database)
    if event_count:
        print(f"Inserted {event_count} synthetic events and generated {alert_count} alerts.")
    else:
        print("Demo skipped: database already contains events; existing data was preserved.")


if __name__ == "__main__":
    main()
