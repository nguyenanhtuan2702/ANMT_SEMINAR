"""Orchestration for normalized log analysis across detector modules."""
from __future__ import annotations

import pandas as pd

from detection.correlation import correlate_events
from detection.ml_engine import predict as ml_predict
from detection.rule_engine import run_rules
from detection.severity import assign_severity
from preprocessing.log_normalizer import normalize_logs


def _ml_alerts(
    predictions: pd.DataFrame,
    model_name: str,
    threshold: float,
) -> pd.DataFrame:
    alert_rows = predictions[predictions["predicted_label"] == 1].copy()
    if alert_rows.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "user",
                "agent",
                "activity",
                "action",
                "rule_id",
                "reason",
                "evidence",
                "source_row_id",
                "alert_id",
                "source",
                "anomaly_score",
            ]
        )
    alert_rows["rule_id"] = "ML_ANOMALY"
    alert_rows["reason"] = alert_rows["anomaly_score"].map(
        lambda score: f"ML anomaly score {score:.4f} meets threshold {threshold:.4f}."
    )
    alert_rows["evidence"] = alert_rows["anomaly_score"].map(
        lambda score: {
            "model": model_name,
            "anomaly_score": float(score),
            "threshold": float(threshold),
        }
    )
    alert_rows["alert_id"] = alert_rows["source_row_id"] + ":ML_ANOMALY"
    alert_rows["source"] = f"ML ({model_name})"
    return alert_rows.rename(
        columns={
            "timestamp": "timestamp",
            "user": "user",
            "agent": "agent",
            "activity": "activity",
        }
    )[
        [
            "timestamp",
            "user",
            "agent",
            "activity",
            "action",
            "rule_id",
            "reason",
            "evidence",
            "source_row_id",
            "alert_id",
            "source",
            "anomaly_score",
        ]
    ]


def analyze_events(
    input_events: pd.DataFrame,
    *,
    model_name: str = "random_forest_behavioral.joblib",
    threshold: float = 0.52,
) -> dict[str, pd.DataFrame | dict[str, int | str]]:
    """Run normalize → ML/rules → correlate → severity for an uploaded file."""
    events = normalize_logs(input_events)
    if events["Timestamp"].isna().all():
        raise ValueError("Không có Timestamp hợp lệ để phân tích.")

    valid_time_events = events[events["Timestamp"].notna()]
    predictions = ml_predict(
        valid_time_events,
        model_name=model_name,
        threshold=threshold,
    )
    rule_alerts = run_rules(events)
    correlated_events, event_groups = correlate_events(events, rule_alerts)

    group_ids = correlated_events.set_index("source_row_id")["group_id"]
    if not rule_alerts.empty:
        rule_alerts["group_id"] = rule_alerts["source_row_id"].map(group_ids)
        rule_alerts["source"] = "Rule Engine"
        rule_alerts["anomaly_score"] = pd.NA
    ml_alerts = _ml_alerts(predictions, model_name, threshold)
    if not ml_alerts.empty:
        ml_alerts["group_id"] = ml_alerts["source_row_id"].map(group_ids)

    alerts = pd.concat([rule_alerts, ml_alerts], ignore_index=True, sort=False)
    if not alerts.empty:
        alerts = assign_severity(correlated_events, alerts)
        rule_alerts = alerts[alerts["source"] == "Rule Engine"].copy()
        ml_alerts = alerts[alerts["source"].str.startswith("ML (")].copy()
    if not alerts.empty:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts["_severity_order"] = alerts["severity"].map(severity_order)
        alerts = (
            alerts.sort_values(
                ["timestamp", "_severity_order", "source_row_id"],
                kind="stable",
            )
            .drop(columns="_severity_order")
            .reset_index(drop=True)
        )

    diagnostics = {
        "input_rows": int(len(events)),
        "invalid_timestamp_rows": int(events["Timestamp"].isna().sum()),
        "ml_scored_rows": int(len(predictions)),
        "ml_alerts": int(len(ml_alerts)),
        "rule_alerts": int(len(rule_alerts)),
        "correlated_groups": int(len(event_groups)),
        "events_without_correlation_group": int(correlated_events["group_id"].isna().sum()),
    }
    return {
        "events": correlated_events,
        "predictions": predictions,
        "rule_alerts": rule_alerts,
        "ml_alerts": ml_alerts,
        "alerts": alerts,
        "event_groups": event_groups,
        "diagnostics": diagnostics,
    }
