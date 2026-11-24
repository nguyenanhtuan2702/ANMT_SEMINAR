"""Deterministic event-level alert schema v1.0; no ground-truth dependencies."""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime
import re

import pandas as pd

from preprocessing.contracts import Alert, MergedAlert
from detection.rule_engine import ALERT_COLUMNS

SCHEMA_VERSION = "1.0"
PRIORITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
# Exact historical summary texts remain valid in frozen, untranslated artifacts.
# Hashes avoid embedding legacy-language messages in English source code while
# preserving strict validation; arbitrary replacement reasons are still rejected.
LEGACY_SUMMARY_SHA256 = {
    "LOW": "16ca5838307728fe7eca00add6eaf6174b99a695ebaadb186091f6dcfa021a4e",
    "MEDIUM": "89294df198edfe2d29b7590d714930aac553d7b30cdc8522919c2abf6a12ab5c",
    "HIGH": "f58c9cb8dabd6d153ff75a08800b38a01327be1cfb81d6a827c5e67635f3fef0",
    "CRITICAL": "c8d4522680157184e7a32271cb6da22f042f57ed0718ccf1db82c159c4a0f876",
}
MERGED_ALERT_COLUMNS = (
    "schema_version", "alert_id", "source_row_id", "timestamp", "user", "agent",
    "activity", "rule_ids", "rule_matches", "reason", "severity", "severity_reason",
)


def validate_atomic_alert(alert: Alert) -> None:
    if not isinstance(alert, dict) or set(alert) != set(ALERT_COLUMNS):
        raise ValueError("Atomic alerts require exactly the 11 contract fields.")
    for key in set(ALERT_COLUMNS) - {"user", "evidence"}:
        if not isinstance(alert[key], str) or not alert[key].strip():
            raise ValueError(f"Atomic alert: {key} must be a nonempty string.")
    if alert["user"] is not None and (not isinstance(alert["user"], str) or not alert["user"].strip()):
        raise ValueError("Atomic alert: user must be a nonempty string or null.")
    if alert["severity"] not in PRIORITY:
        raise ValueError("Invalid atomic alert severity.")
    if not re.fullmatch(r"[0-9a-f]{64}:[0-9]{8,}", alert["source_row_id"]):
        raise ValueError("source_row_id v1.0 requires SHA256:record_index padded to at least 8 digits.")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", alert["rule_id"]):
        raise ValueError("Invalid atomic alert rule_id.")
    if alert["alert_id"] != alert["source_row_id"]+":"+alert["rule_id"]:
        raise ValueError("Atomic alert_id does not match source_row_id/rule_id.")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}", alert["timestamp"]):
        raise ValueError("Atomic timestamp must use timezone-naive ISO milliseconds.")
    datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
    evidence = alert["evidence"]
    if (not isinstance(evidence, dict) or any(not isinstance(k, str) or k in {"Anomaly", "Level"}
            or (v is not None and not isinstance(v, str)) for k, v in evidence.items())):
        raise ValueError("evidence must map strings to strings/null and must not contain labels/Level.")


def merge_alerts(alerts: list[Alert]) -> list[MergedAlert]:
    """One event per source_row_id; retain sorted rule_ids and all rule evidence.

    Exact repeat delivery of (source_row_id, rule_id) is idempotently removed.
    Conflicting repeat alerts or event contexts raise ValueError. Distinct source
    rows are never collapsed merely because their raw text/timestamp is equal.
    """
    groups = {}
    for alert in alerts:
        validate_atomic_alert(alert)
        sid, rid = alert["source_row_id"], alert["rule_id"]
        group = groups.setdefault(sid, {})
        if rid in group:
            if group[rid] != alert:
                raise ValueError(f"Duplicate alert key with conflicting content: {sid}/{rid}.")
            continue
        if group:
            first = next(iter(group.values()))
            if any(first[c] != alert[c] for c in ("timestamp", "user", "agent", "activity")):
                raise ValueError(f"Inconsistent event context: {sid}.")
        group[rid] = copy.deepcopy(alert)
    merged = []
    for sid, by_rule in groups.items():
        rule_ids = sorted(by_rule)
        first = by_rule[rule_ids[0]]
        severity = max((a["severity"] for a in by_rule.values()), key=PRIORITY.__getitem__)
        item = {
            "schema_version": SCHEMA_VERSION, "alert_id": sid+":merged:v1.0",
            "source_row_id": sid,
            **{key: first[key] for key in ("timestamp", "user", "agent", "activity")},
            "rule_ids": rule_ids,
            "rule_matches": [{key: by_rule[rid][key] for key in
                             ("alert_id", "rule_id", "reason", "evidence", "severity", "severity_reason")}
                             for rid in rule_ids],
            "reason": " | ".join(rid+": "+by_rule[rid]["reason"] for rid in rule_ids),
            "severity": severity,
            "severity_reason": "Highest prototype priority among matched rules: "+severity+"; not verified impact.",
        }
        merged.append(item)
    return sorted(merged, key=lambda item: (item["timestamp"], item["source_row_id"]))


def validate_merged_alert(alert: MergedAlert) -> None:
    if not isinstance(alert, dict) or set(alert) != set(MERGED_ALERT_COLUMNS):
        raise ValueError("Merged alert v1.0 requires exactly 12 fields.")
    if alert["schema_version"] != SCHEMA_VERSION:
        raise ValueError("schema_version must be 1.0.")
    ids, matches = alert["rule_ids"], alert["rule_matches"]
    if (not isinstance(ids, list) or not ids or any(not isinstance(rid, str) for rid in ids)
            or ids != sorted(set(ids)) or not isinstance(matches, list) or len(matches) != len(ids)):
        raise ValueError("Invalid or duplicate rule_ids/rule_matches.")
    atomic = []
    for match in matches:
        if not isinstance(match, dict) or set(match) != {"alert_id", "rule_id", "reason", "evidence", "severity", "severity_reason"}:
            raise ValueError("Invalid rule_match schema.")
        atomic.append({**{key: alert[key] for key in ("source_row_id", "timestamp", "user", "agent", "activity")}, **match})
    rebuilt = merge_alerts(atomic)
    summary = alert.get("severity_reason")
    if (len(rebuilt) == 1 and isinstance(summary, str)
            and hashlib.sha256(summary.encode("utf-8")).hexdigest() == LEGACY_SUMMARY_SHA256[rebuilt[0]["severity"]]):
        rebuilt[0]["severity_reason"] = summary
    if len(rebuilt) != 1 or rebuilt[0] != alert:
        raise ValueError("Merged alert is inconsistent with its rule_matches.")


def merged_alerts_to_dataframe(alerts: list[MergedAlert]) -> pd.DataFrame:
    for alert in alerts:
        validate_merged_alert(alert)
    frame = pd.DataFrame(alerts, columns=MERGED_ALERT_COLUMNS)
    for column in MERGED_ALERT_COLUMNS:
        if column not in {"rule_ids", "rule_matches"}:
            frame[column] = frame[column].astype("string")
    return frame
