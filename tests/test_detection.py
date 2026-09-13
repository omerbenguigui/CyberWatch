from datetime import UTC, datetime, timedelta

from app.database import Database
from app.detection import DetectionEngine
from app.models import EventType, LogEventCreate, Severity


def make_engine(tmp_path):
    database = Database(tmp_path / "test.db")
    database.initialize()
    return database, DetectionEngine(database)


def add_and_evaluate(database, engine, event):
    stored = database.insert_event(event)
    return engine.evaluate(stored)


def test_brute_force_rule_fires_on_fifth_failure(tmp_path):
    database, engine = make_engine(tmp_path)
    now = datetime.now(UTC)
    alerts = []
    for index in range(5):
        alerts += add_and_evaluate(
            database,
            engine,
            LogEventCreate(
                timestamp=now + timedelta(seconds=index),
                event_type=EventType.LOGIN_FAILED,
                source_ip="203.0.113.10",
                username="admin",
                message="Invalid password",
            ),
        )
    assert len(alerts) == 1
    assert alerts[0].rule_id == "CW-AUTH-001"
    assert alerts[0].severity is Severity.HIGH
    assert alerts[0].evidence["failed_attempts"] == 5


def test_brute_force_rule_ignores_attempts_outside_window(tmp_path):
    database, engine = make_engine(tmp_path)
    now = datetime.now(UTC)
    alerts = []
    for index in range(5):
        alerts += add_and_evaluate(
            database,
            engine,
            LogEventCreate(
                timestamp=now + timedelta(minutes=index * 2),
                event_type=EventType.LOGIN_FAILED,
                source_ip="203.0.113.11",
            ),
        )
    assert alerts == []


def test_port_scan_rule_counts_distinct_ports(tmp_path):
    database, engine = make_engine(tmp_path)
    now = datetime.now(UTC)
    alerts = []
    for index in range(10):
        alerts += add_and_evaluate(
            database,
            engine,
            LogEventCreate(
                timestamp=now + timedelta(seconds=index),
                event_type=EventType.NETWORK_CONNECTION,
                source_ip="198.51.100.3",
                destination_ip="10.0.0.5",
                destination_port=1000 + index,
            ),
        )
    assert len(alerts) == 1
    assert alerts[0].rule_id == "CW-NET-001"
    assert alerts[0].severity is Severity.CRITICAL


def test_alert_cooldown_prevents_duplicates(tmp_path):
    database, engine = make_engine(tmp_path)
    now = datetime.now(UTC)
    alerts = []
    for index in range(7):
        alerts += add_and_evaluate(
            database,
            engine,
            LogEventCreate(
                timestamp=now + timedelta(seconds=index),
                event_type=EventType.LOGIN_FAILED,
                source_ip="192.0.2.50",
            ),
        )
    assert len(alerts) == 1


def test_suspicious_process_rule_is_case_insensitive(tmp_path):
    database, engine = make_engine(tmp_path)
    alerts = add_and_evaluate(
        database,
        engine,
        LogEventCreate(
            event_type=EventType.PROCESS_START,
            source_ip="10.0.0.20",
            message="PowerShell started",
            metadata={"command_line": "powershell -ENCODEDCOMMAND [redacted]"},
        ),
    )
    assert len(alerts) == 1
    assert alerts[0].rule_id == "CW-ENDPOINT-001"


def test_benign_process_does_not_create_alert(tmp_path):
    database, engine = make_engine(tmp_path)
    alerts = add_and_evaluate(
        database,
        engine,
        LogEventCreate(
            event_type=EventType.PROCESS_START,
            source_ip="10.0.0.20",
            message="Browser update",
            metadata={"command_line": "browser-updater --silent"},
        ),
    )
    assert alerts == []
