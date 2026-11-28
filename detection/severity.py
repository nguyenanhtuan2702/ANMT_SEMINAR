"""Prototype processing priority, never verified impact; no labels or ML scoring.

Score atomic alerts BEFORE merge_alerts(). Recompute causal prefix context from
normalized events; never use final group totals to score a past alert. Raw evidence
and detection reason are copied unchanged. ML is an ignored API extension slot.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pandas as pd

from detection.alert_aggregation import PRIORITY, merge_alerts, validate_atomic_alert
from detection.correlation import correlate
from detection.rule_engine import load_rule_config
from preprocessing.contracts import Alert

DEFAULT_CONFIG = Path(__file__).with_name("severity_policy.json")
LEVELS = tuple(PRIORITY)


def load_severity_config(config: dict | str | Path | None = None) -> dict:
    """Read a complete policy; thresholds are not fitted from labels."""
    policy = (json.loads(Path(config or DEFAULT_CONFIG).read_text(encoding="utf-8"))
              if not isinstance(config, dict) else copy.deepcopy(config))
    expected = {"schema_version", "alert_thresholds", "activity_threshold", "activity_steps",
                "working_hour_start", "working_hour_end", "off_hours_steps", "max_context_steps", "correlation"}
    if not isinstance(policy, dict) or set(policy) != expected or policy["schema_version"] != "spedia.severity.v1":
        raise ValueError("Invalid severity policy schema/fields/version.")
    for field in ("activity_threshold", "activity_steps", "working_hour_start", "working_hour_end", "off_hours_steps", "max_context_steps"):
        if type(policy[field]) is not int:
            raise ValueError(f"{field} must be an integer, not a boolean.")
    if not (0 <= policy["working_hour_start"] < policy["working_hour_end"] <= 24):
        raise ValueError("Working hours require 0 <= start < end <= 24.")
    if policy["activity_threshold"] < 2 or any(not 0 <= policy[k] <= 3 for k in ("activity_steps", "off_hours_steps", "max_context_steps")):
        raise ValueError("The activity threshold must be >= 2; adjustment steps must be in 0..3.")
    thresholds = policy["alert_thresholds"]
    if not isinstance(thresholds, list) or not thresholds:
        raise ValueError("alert_thresholds must be a nonempty list.")
    previous_count, previous_steps = 1, 0
    for item in thresholds:
        if (not isinstance(item, dict) or set(item) != {"count", "steps"}
                or type(item["count"]) is not int or type(item["steps"]) is not int
                or item["count"] <= previous_count or not previous_steps <= item["steps"] <= 3):
            raise ValueError("Alert thresholds must increase, count must be >= 2, and steps must be nondecreasing within 0..3.")
        previous_count, previous_steps = item["count"], item["steps"]
    corr = policy["correlation"]
    if (not isinstance(corr, dict) or set(corr) != {"window_seconds", "max_gap_seconds", "min_events"}
            or any(type(v) is not int or v <= 0 for v in corr.values())):
        raise ValueError("Severity correlation config requires all three positive integers.")
    return policy


def _context(events: pd.DataFrame, alerts: list[Alert], correlations, policy: dict, canonical_groups=None) -> pd.DataFrame:
    # Canonical membership is independent of alert labels and future group totals.
    # The pipeline may reuse groups it just produced with correlate() on these
    # exact events/policy. The public assign_severity API always recomputes them.
    groups = correlate(events, [], config=policy["correlation"]) if canonical_groups is None else canonical_groups
    if correlations is not None and canonical_groups is None:
        if isinstance(correlations, pd.DataFrame):
            supplied = correlations.to_dict("records")
        elif isinstance(correlations, list):
            supplied = correlations
        else:
            raise TypeError("correlations must be a correlate() DataFrame or a list from the Correlation adapter.")
        canonical = dict(zip(groups.group_id, groups.source_row_ids))
        selected, seen = [], set()
        for group in supplied:
            if not isinstance(group, dict):
                raise ValueError("Correlation must be a dictionary.")
            gid = group.get("group_id", group.get("correlation_id"))
            if not isinstance(gid, str) or gid in seen or gid not in canonical or group.get("source_row_ids") != canonical[gid]:
                raise ValueError("Correlation does not match events/config/snapshot; arbitrary groups or different cutoffs are not supported.")
            seen.add(gid)
            selected.append(gid)
        groups = groups.loc[groups.group_id.isin(selected)]
    core = events.loc[:, ["source_row_id", "Timestamp", "record_index", "User", "Agent_name", "Activity"]].copy()
    # Validate every alert against its source event, including ungrouped events.
    refs = pd.DataFrame(alerts).drop_duplicates("source_row_id")
    joined = refs.merge(core, on="source_row_id", how="left", indicator=True, validate="one_to_one")
    if joined["_merge"].ne("both").any():
        raise ValueError("Alert source_row_id not found in events.")
    for source, alert in (("Timestamp", "timestamp"), ("User", "user"), ("Agent_name", "agent"), ("Activity", "activity")):
        left = joined[source]
        right = pd.to_datetime(joined[alert], format="%Y-%m-%dT%H:%M:%S.%f") if source == "Timestamp" else joined[alert]
        equal = left.eq(right) | (left.isna() & right.isna())
        if not equal.fillna(False).all():
            raise ValueError(f"Alert {alert} does not match the source event.")
    membership = groups[["group_id", "source_row_ids"]].explode("source_row_ids").rename(columns={"source_row_ids": "source_row_id"})
    if membership.empty:
        return pd.DataFrame(columns=["alert_events", "activity_types"], index=pd.Index([], name="source_row_id"))
    visible = membership.merge(core, on="source_row_id", validate="one_to_one").sort_values(["Timestamp", "record_index"], kind="stable")
    visible["has_alert"] = visible.source_row_id.isin(refs.source_row_id).astype("int64")
    visible["alert_events"] = visible.groupby("group_id", sort=False).has_alert.cumsum()
    valid_activity = visible.Activity.notna() & visible.Activity.astype("string").str.strip().ne("").fillna(False)
    visible["new_activity"] = (~visible.duplicated(["group_id", "Activity"]) & valid_activity).astype("int64")
    visible["activity_types"] = visible.groupby("group_id", sort=False).new_activity.cumsum()
    return visible.set_index("source_row_id")[["alert_events", "activity_types"]]


def _assign_severity(
    alerts: list[Alert], correlations=None, ml_results=None, *,
    events: pd.DataFrame | None = None, config: dict | str | Path | None = None,
    canonical_groups=None,
) -> list[Alert]:
    """Return copied atomic alerts with severity + severity_reason.

    Base levels come from rules.json, not incoming severity. Group context counts
    unique alerted source rows through each anchor (Timestamp, record_index).
    events=None enables base + source-clock hour only; correlations require events.
    Pass events already cut to as_of for snapshots. ml_results is intentionally
    NOT read, validated or applied. Call merge_alerts(result) for merged v1.0.
    """
    policy = load_severity_config(config)
    if not isinstance(alerts, list):
        raise TypeError("alerts must be an atomic list; for merged input, use the original Task 4 atomic alerts.")
    for alert in alerts:
        validate_atomic_alert(alert)
    merge_alerts(alerts)  # reject conflicting repeat delivery / inconsistent context
    bases = {r["rule_id"]: r["base_severity"] for r in load_rule_config()["rules"]}
    unknown = sorted({a["rule_id"] for a in alerts} - bases.keys())
    if unknown:
        raise ValueError("Missing severity mapping for rule_id: " + ", ".join(unknown))
    if correlations is not None and events is None:
        raise ValueError("Normalized events are required to calculate causal prefixes when correlations are provided.")
    if not alerts:
        return []
    context = _context(events, alerts, correlations, policy, canonical_groups) if events is not None else None
    result = copy.deepcopy(alerts)
    for alert in result:
        base = bases[alert["rule_id"]]
        count, activities = 0, 0
        grouped = context is not None and alert["source_row_id"] in context.index
        if grouped:
            row = context.loc[alert["source_row_id"]]
            count, activities = int(row.alert_events), int(row.activity_types)
        count_steps = max((t["steps"] for t in policy["alert_thresholds"] if count >= t["count"]), default=0)
        activity_steps = policy["activity_steps"] if activities >= policy["activity_threshold"] else 0
        hour = pd.Timestamp(alert["timestamp"]).hour
        off_hours = not policy["working_hour_start"] <= hour < policy["working_hour_end"]
        hour_steps = policy["off_hours_steps"] if off_hours else 0
        total = min(count_steps + activity_steps + hour_steps, policy["max_context_steps"])
        severity = LEVELS[min(PRIORITY[base]+total, 3)]
        context_note = (f"group prefix: {count} alerted events (+{count_steps}), {activities} activity types (+{activity_steps})"
                        if grouped else "no eligible group context; count/activity +0")
        alert["severity"] = severity
        alert["severity_reason"] = (
            f"Prototype processing priority, not verified impact. Policy spedia.severity.v1; "
            f"rule {alert['rule_id']} base={base}; {context_note}; source hour={hour:02d}, "
            f"outside [{policy['working_hour_start']:02d}:00,{policy['working_hour_end']:02d}:00)={off_hours} (+{hour_steps}); "
            f"total increase={total} levels (context limit {policy['max_context_steps']}, CRITICAL ceiling) → {severity}. "
            "No automatic decrease for missing context/working hours; ML is not used."
        )
    return result


def assign_severity(
    alerts: list[Alert], correlations=None, ml_results=None, *,
    events: pd.DataFrame | None = None, config: dict | str | Path | None = None,
) -> list[Alert]:
    """Copied atomic priorities/reasons; validate groups and count only prefixes.

    events is required with correlations. No group summaries, Anomaly, Level or
    ML scores are used. See SEVERITY_POLICY.md for the complete public contract.
    """
    return _assign_severity(alerts, correlations, ml_results, events=events, config=config)
