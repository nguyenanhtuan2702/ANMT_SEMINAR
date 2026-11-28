"""Shared pipeline types; individual implementations are tracked in docs."""
from typing import Literal, TypedDict

REQUIRED_COLUMNS = ("id", "Timestamp", "Agent_name", "User", "Activity", "Action")
RAW_COLUMNS = ("Full_log", "Description", "Content")
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Alert(TypedDict):
    alert_id: str
    source_row_id: str
    timestamp: str
    user: str | None
    agent: str
    activity: str
    rule_id: str
    reason: str
    evidence: dict[str, str | None]
    severity: Severity | None
    severity_reason: str | None


class RuleMatch(TypedDict):
    alert_id: str
    rule_id: str
    reason: str
    evidence: dict[str, str | None]
    severity: Severity
    severity_reason: str


class MergedAlert(TypedDict):
    schema_version: str
    alert_id: str
    source_row_id: str
    timestamp: str
    user: str | None
    agent: str
    activity: str
    rule_ids: list[str]
    rule_matches: list[RuleMatch]
    reason: str
    severity: Severity
    severity_reason: str


class Correlation(TypedDict):
    correlation_id: str
    correlation_rule_id: str
    anchor_source_row_id: str
    source_row_ids: list[str]
    window_start: str
    window_end: str
    user: str | None
    agent: str
    reason: str


class RuleDefinition(TypedDict):
    rule_id: str
    enabled: bool
    condition: str
    params: dict
    reason_template: str
    base_severity: Severity
    severity_reason: str
    rationale: str


class RuleConfig(TypedDict, total=False):
    schema_version: str
    rules: list[RuleDefinition]
    enabled_rule_ids: list[str]


class CorrelationConfig(TypedDict, total=False):
    window_seconds: int
    max_gap_seconds: int
    min_events: int


class EventGroup(TypedDict):
    group_id: str
    key: dict[str, str]
    user: str
    agent: str
    start_time: str
    end_time: str
    event_count: int
    activities: list[str]
    alert_count: int | None
    rule_match_count: int | None
    rule_ids: list[str]
    source_row_ids: list[str]


class MLResult(TypedDict):
    source_row_id: str
    predicted_label: int
    anomaly_score: float
