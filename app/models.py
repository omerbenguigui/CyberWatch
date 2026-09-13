"""API schemas shared by the application and detection engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    NETWORK_CONNECTION = "network_connection"
    PROCESS_START = "process_start"
    FILE_ACCESS = "file_access"
    FIREWALL_BLOCK = "firewall_block"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"


class LogEventCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: EventType
    source_ip: str = Field(min_length=3, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=128)
    message: str = Field(default="", max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class LogEvent(LogEventCreate):
    id: int


class Alert(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    source_ip: str
    evidence: dict[str, Any]


class AlertCreate(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_id: str
    title: str
    description: str
    severity: Severity
    source_ip: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class DashboardSummary(BaseModel):
    total_events: int
    open_alerts: int
    critical_alerts: int
    unique_sources: int
    events_by_type: dict[str, int]
    alerts_by_severity: dict[str, int]


class BatchIngestResult(BaseModel):
    accepted: int
    generated_alerts: int
    event_ids: list[int]
