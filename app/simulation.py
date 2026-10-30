"""Safe synthetic attack scenarios for the local portfolio demo."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from app.database import Database
from app.detection import DetectionEngine
from app.models import DemoSimulationResult, EventType, LogEventCreate


class DemoScenario(StrEnum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_PROCESS = "suspicious_process"


def run_simulation(
    database: Database, detector: DetectionEngine, scenario: DemoScenario
) -> DemoSimulationResult:
    """Insert synthetic telemetry only; no network activity or commands are executed."""
    now = datetime.now(UTC)
    source_ip = f"2001:db8::{uuid4().hex[:6]}"

    if scenario is DemoScenario.BRUTE_FORCE:
        payloads = [
            LogEventCreate(
                timestamp=now - timedelta(seconds=4 - index),
                event_type=EventType.LOGIN_FAILED,
                source_ip=source_ip,
                destination_ip="10.0.0.5",
                destination_port=22,
                username="administrator",
                message="Invalid password in simulated attack",
                metadata={"simulation": True},
            )
            for index in range(5)
        ]
    elif scenario is DemoScenario.PORT_SCAN:
        payloads = [
            LogEventCreate(
                timestamp=now - timedelta(seconds=9 - index),
                event_type=EventType.NETWORK_CONNECTION,
                source_ip=source_ip,
                destination_ip="10.0.0.12",
                destination_port=8000 + index,
                message="Connection attempt in simulated port scan",
                metadata={"simulation": True},
            )
            for index in range(10)
        ]
    else:
        payloads = [
            LogEventCreate(
                timestamp=now,
                event_type=EventType.PROCESS_START,
                source_ip=source_ip,
                username="demo-user",
                message="Suspicious PowerShell process in simulated attack",
                metadata={
                    "simulation": True,
                    "command_line": "powershell.exe -EncodedCommand [safe-demo-value]",
                },
            )
        ]

    alert_count = 0
    for payload in payloads:
        event = database.insert_event(payload)
        alert_count += len(detector.evaluate(event))

    return DemoSimulationResult(
        scenario=scenario.value,
        accepted=len(payloads),
        generated_alerts=alert_count,
        source_ip=source_ip,
    )
