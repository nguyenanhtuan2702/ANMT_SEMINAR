"""Explainable priority levels combining rule and ML corroboration."""
from __future__ import annotations

import pandas as pd

from detection.rule_engine import RULE_SEVERITIES
from preprocessing.source_ids import validate_source_row_ids


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def assign_severity(
    events: pd.DataFrame,
    alerts: pd.DataFrame,
) -> pd.DataFrame:
    """Assign alert priority using rule evidence and causal group prefixes."""
    required_events = {
        "source_row_id",
        "Timestamp",
        "group_id",
    }
    missing_events = required_events - set(events.columns)
    if missing_events:
        raise ValueError(
            "Severity thiếu cột event: " + ", ".join(sorted(missing_events))
        )
    required_alerts = {"source_row_id", "rule_id", "source"}
    missing_alerts = required_alerts - set(alerts.columns)
    if missing_alerts:
        raise ValueError(
            "Severity thiếu cột alert: " + ", ".join(sorted(missing_alerts))
        )
    events = events.copy()
    alerts = alerts.copy()
    events["source_row_id"] = validate_source_row_ids(
        events,
        component="Severity events",
    )
    alerts["source_row_id"] = validate_source_row_ids(
        alerts,
        component="Severity alerts",
        unique=False,
    )
    if alerts.empty:
        result = alerts.copy()
        result["base_severity"] = pd.Series(dtype="string")
        result["severity"] = pd.Series(dtype="string")
        result["severity_reason"] = pd.Series(dtype="string")
        return result

    is_ml = alerts["rule_id"].eq("ML_ANOMALY")
    unknown_rules = sorted(set(alerts.loc[~is_ml, "rule_id"]) - set(RULE_SEVERITIES))
    if unknown_rules:
        raise ValueError("Chưa có severity cho rule: " + ", ".join(unknown_rules))
    known_source_ids = set(events["source_row_id"].astype(str))
    rule_signals: dict[str, set[str]] = {}
    ml_signals: set[str] = set()
    for alert in alerts.itertuples(index=False):
        source_id = str(alert.source_row_id)
        if source_id not in known_source_ids:
            raise ValueError(f"Alert trỏ tới source_row_id không tồn tại: {source_id}")
        if str(alert.rule_id) == "ML_ANOMALY":
            ml_signals.add(source_id)
        else:
            rule_signals.setdefault(source_id, set()).add(str(alert.rule_id))

    context_fields = ["source_row_id", "Timestamp", "group_id"]
    if "record_index" in events.columns:
        context_fields.append("record_index")
    grouped = events.loc[
        events["group_id"].notna() & events["Timestamp"].notna(),
        context_fields,
    ].copy()
    sort_columns = ["group_id", "Timestamp"]
    if "record_index" in grouped.columns:
        sort_columns.append("record_index")
    grouped = grouped.sort_values(sort_columns, kind="stable")
    source_ids = grouped["source_row_id"].astype(str)
    group_ids = grouped["group_id"]
    has_rule_alert = source_ids.isin(rule_signals)
    has_ml_alert = source_ids.isin(ml_signals)
    grouped["_prefix_rule_events"] = (
        has_rule_alert.astype("int64").groupby(group_ids, sort=False).cumsum()
    )
    grouped["_prefix_ml_events"] = (
        has_ml_alert.astype("int64").groupby(group_ids, sort=False).cumsum()
    )
    new_rule_type_count = pd.Series(0, index=grouped.index, dtype="int64")
    for rule_id in sorted(RULE_SEVERITIES):
        matching_source_ids = {
            source_id
            for source_id, matched_rules in rule_signals.items()
            if rule_id in matched_rules
        }
        type_match = source_ids.isin(matching_source_ids)
        first_type_match = (
            type_match
            & type_match.groupby(group_ids, sort=False).cumsum().eq(1)
        )
        new_rule_type_count += first_type_match.astype("int64")
    grouped["_prefix_rule_types"] = (
        new_rule_type_count.groupby(group_ids, sort=False).cumsum()
    )
    prefix_by_id = grouped.set_index("source_row_id")[
        ["_prefix_rule_events", "_prefix_rule_types", "_prefix_ml_events"]
    ]

    result = alerts.copy()
    if "group_id" not in result.columns:
        group_by_id = events.set_index(events["source_row_id"].astype(str))["group_id"]
        result["group_id"] = result["source_row_id"].astype(str).map(group_by_id)
    result_source_ids = result["source_row_id"].astype(str)
    prefix = prefix_by_id.reindex(result_source_ids.to_numpy())
    prefix.index = result.index
    rule_event_count = prefix["_prefix_rule_events"].fillna(0).astype("int64")
    rule_type_count = prefix["_prefix_rule_types"].fillna(0).astype("int64")
    ml_event_count = prefix["_prefix_ml_events"].fillna(0).astype("int64")
    current_rule_types = result_source_ids.map(
        {source_id: len(rule_ids) for source_id, rule_ids in rule_signals.items()}
    ).fillna(0).astype("int64")
    current_has_ml = result_source_ids.isin(ml_signals)
    is_corroborated = (
        (current_has_ml & current_rule_types.gt(0))
        | current_rule_types.ge(2)
    )
    repeated_or_diverse = rule_event_count.ge(3) | rule_type_count.ge(2)
    critical_convergence = (
        rule_event_count.ge(10)
        & rule_type_count.ge(3)
        & ml_event_count.gt(0)
    )

    base_severity = result["rule_id"].map(RULE_SEVERITIES)
    base_severity = base_severity.mask(result["rule_id"].eq("ML_ANOMALY"), "LOW")
    final_level = base_severity.map(SEVERITY_ORDER).astype("int64")
    final_level = final_level.where(
        ~(is_corroborated | repeated_or_diverse),
        final_level.clip(lower=SEVERITY_ORDER["HIGH"]),
    )
    final_level = final_level.where(
        ~critical_convergence,
        SEVERITY_ORDER["CRITICAL"],
    )
    result["base_severity"] = base_severity
    result["severity"] = final_level.map(
        {level: name for name, level in SEVERITY_ORDER.items()}
    )

    reason_rows = zip(
        result["rule_id"].astype(str),
        result["anomaly_score"] if "anomaly_score" in result.columns else [pd.NA] * len(result),
        base_severity,
        current_rule_types,
        current_has_ml,
        rule_event_count,
        rule_type_count,
        ml_event_count,
        is_corroborated,
        repeated_or_diverse,
        critical_convergence,
        final_level,
    )
    result["severity_reason"] = [
        (
            f"{'ML anomaly score=' + str(score) if rule_id == 'ML_ANOMALY' else 'rule=' + rule_id}; "
            f"base={base}; same-event rule types={int(same_rule_types)}, "
            f"same-event ML={'yes' if has_ml else 'no'}, "
            f"causal prefix rule-alert events={int(prefix_rules)}, "
            f"distinct rule types={int(prefix_types)}, "
            f"ML-alert events={int(prefix_ml)}; "
            f"corroboration={'yes' if corroborated else 'no'}, "
            f"repetition/diversity={'yes' if repeated else 'no'}, "
            f"critical convergence={'yes' if critical else 'no'}; "
            f"final={SEVERITY_NAMES[int(final)]}. "
            "Severity is a review priority, not a confirmed impact rating."
        )
        for (
            rule_id,
            score,
            base,
            same_rule_types,
            has_ml,
            prefix_rules,
            prefix_types,
            prefix_ml,
            corroborated,
            repeated,
            critical,
            final,
        ) in reason_rows
    ]
    return result
