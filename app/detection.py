"""Rule-based threat detection for incoming security events."""

from __future__ import annotations

from datetime import timedelta

from app.database import Database
from app.models import Alert, AlertCreate, EventType, LogEvent, Severity


class DetectionEngine:
    """Evaluate events against explainable security rules."""

    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = timedelta(minutes=5)
    PORT_SCAN_THRESHOLD = 10
    PORT_SCAN_WINDOW = timedelta(minutes=2)
    ALERT_COOLDOWN = timedelta(minutes=10)
    SUSPICIOUS_PROCESS_TOKENS = (
        "-encodedcommand",
        "frombase64string",
        "mimikatz",
        "invoke-expression",
        "downloadstring(",
    )

    def __init__(self, database: Database) -> None:
        self.database = database

    def evaluate(self, event: LogEvent) -> list[Alert]:
        candidates: list[AlertCreate] = []

        brute_force = self._detect_brute_force(event)
        if brute_force:
            candidates.append(brute_force)

        port_scan = self._detect_port_scan(event)
        if port_scan:
            candidates.append(port_scan)

        suspicious_process = self._detect_suspicious_process(event)
        if suspicious_process:
            candidates.append(suspicious_process)

        alerts: list[Alert] = []
        for candidate in candidates:
            cooldown_start = event.timestamp - self.ALERT_COOLDOWN
            if not self.database.has_recent_alert(
                candidate.rule_id, candidate.source_ip, cooldown_start
            ):
                alerts.append(self.database.create_alert(candidate))
        return alerts

    def _detect_brute_force(self, event: LogEvent) -> AlertCreate | None:
        if event.event_type is not EventType.LOGIN_FAILED:
            return None
        failures = self.database.list_events(
            limit=self.BRUTE_FORCE_THRESHOLD,
            event_type=EventType.LOGIN_FAILED.value,
            source_ip=event.source_ip,
            since=event.timestamp - self.BRUTE_FORCE_WINDOW,
        )
        if len(failures) < self.BRUTE_FORCE_THRESHOLD:
            return None
        usernames = sorted({failure.username for failure in failures if failure.username})
        return AlertCreate(
            created_at=event.timestamp,
            rule_id="CW-AUTH-001",
            title="Possible brute-force attack",
            description=(
                f"{len(failures)} failed sign-in attempts from {event.source_ip} "
                "were observed within five minutes."
            ),
            severity=Severity.HIGH,
            source_ip=event.source_ip,
            evidence={"failed_attempts": len(failures), "usernames": usernames},
        )

    def _detect_port_scan(self, event: LogEvent) -> AlertCreate | None:
        if event.event_type is not EventType.NETWORK_CONNECTION:
            return None
        port_count = self.database.count_distinct_ports(
            event.source_ip, event.timestamp - self.PORT_SCAN_WINDOW
        )
        if port_count < self.PORT_SCAN_THRESHOLD:
            return None
        return AlertCreate(
            created_at=event.timestamp,
            rule_id="CW-NET-001",
            title="Port scan detected",
            description=(
                f"Source {event.source_ip} contacted {port_count} distinct ports "
                "within two minutes."
            ),
            severity=Severity.CRITICAL,
            source_ip=event.source_ip,
            evidence={"distinct_ports": port_count, "window_seconds": 120},
        )

    def _detect_suspicious_process(self, event: LogEvent) -> AlertCreate | None:
        if event.event_type is not EventType.PROCESS_START:
            return None
        command = f"{event.message} {event.metadata.get('command_line', '')}".lower()
        matches = [token for token in self.SUSPICIOUS_PROCESS_TOKENS if token in command]
        if not matches:
            return None
        return AlertCreate(
            created_at=event.timestamp,
            rule_id="CW-ENDPOINT-001",
            title="Suspicious process execution",
            description=(
                "A process command line matched indicators commonly associated "
                "with malicious script execution."
            ),
            severity=Severity.CRITICAL,
            source_ip=event.source_ip,
            evidence={"matched_indicators": matches},
        )
