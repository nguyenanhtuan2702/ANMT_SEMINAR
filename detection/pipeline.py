"""Rule → Correlation → Severity, with causal per-source-row features (no ML)."""
from __future__ import annotations

import copy
import time
from typing import TypedDict

import pandas as pd

from detection.alert_aggregation import merge_alerts, merged_alerts_to_dataframe
from detection.correlation import correlate
from detection.rule_engine import detect_rules
from detection.severity import _assign_severity, load_severity_config

DETECTION_COLUMNS = ("rule_ids", "alert_count", "group_id", "severity")


class PipelineResult(TypedDict):
    status: str
    detected_logs: pd.DataFrame
    atomic_alerts: list[dict]
    alerts: list[dict]
    alert_table: pd.DataFrame
    groups: pd.DataFrame
    report: dict


class PipelineError(ValueError):
    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = copy.deepcopy(report)


def run_detection_pipeline(df_normalized: pd.DataFrame, *, severity_config=None) -> PipelineResult:
    """Return detected_logs, prioritized atomic/merged alerts, groups and timings.

    Join on source_row_id, preserving input order/index/raw/labels. alert_count is
    the CURRENT EVENT's number of distinct matched rules, not a final group total.
    No-alert severity is null. Group summaries are for display, never ML features
    of past rows. For inference pass complete history through the desired cutoff.
    """
    started = time.perf_counter()
    report = {"status": "running", "stage": "validation", "timings_seconds": {}}
    try:
        if not isinstance(df_normalized, pd.DataFrame):
            raise TypeError("Pipeline requires a normalized DataFrame.")
        if not df_normalized.columns.is_unique:
            raise ValueError("Duplicate normalized column names.")
        collision = sorted(set(DETECTION_COLUMNS).intersection(df_normalized.columns))
        if collision:
            raise ValueError("Input already contains detection columns: " + ", ".join(collision))
        policy = load_severity_config(severity_config)
        if policy["correlation"]["min_events"] != 1:
            raise ValueError("Pipeline requires min_events=1 so group_id does not depend on future events.")
        # Labels remain in returned logs for evaluation only, never in detectors.
        work = df_normalized.drop(columns=["Anomaly", "Level"], errors="ignore").reset_index(drop=True).copy()
        work.attrs = {}
        rule_report, correlation_report = {}, {}
        report["stage"] = "rules"
        step = time.perf_counter()
        base_atomic = detect_rules(work, report=rule_report)
        report["timings_seconds"]["rules"] = time.perf_counter()-step
        report["rules"] = rule_report
        report["stage"] = "correlation"
        step = time.perf_counter()
        groups = correlate(work, base_atomic, config=policy["correlation"], report=correlation_report)
        report["timings_seconds"]["correlation"] = time.perf_counter()-step
        report["correlation"] = correlation_report
        report["stage"] = "severity"
        step = time.perf_counter()
        # Reuse only the canonical groups just computed in this pipeline call.
        # External callers still use assign_severity(), which validates membership.
        atomic = _assign_severity(base_atomic, events=work, config=policy, canonical_groups=groups)
        report["timings_seconds"]["severity"] = time.perf_counter()-step
        report["stage"] = "merge_attach"
        step = time.perf_counter()
        alerts = merge_alerts(atomic)
        table = merged_alerts_to_dataframe(alerts)
        by_source = {a["source_row_id"]: a for a in alerts}
        result = df_normalized.copy(deep=True)
        result.attrs = copy.deepcopy(df_normalized.attrs)
        result["rule_ids"] = result.source_row_id.map(lambda sid: list(by_source[sid]["rule_ids"]) if sid in by_source else []).astype(object)
        result["alert_count"] = result.rule_ids.str.len().astype("Int64")
        membership = groups[["group_id", "source_row_ids"]].explode("source_row_ids").dropna(subset=["source_row_ids"])
        gid = membership.set_index("source_row_ids").group_id
        result["group_id"] = result.source_row_id.map(gid).astype("string")
        levels = {sid: a["severity"] for sid, a in by_source.items()}
        result["severity"] = result.source_row_id.map(levels).astype("string")
        report["timings_seconds"]["merge_attach"] = time.perf_counter()-step
        report.update(status="success", stage="complete", rows_input=len(result),
                      atomic_alert_count=len(atomic), alerted_event_count=len(alerts), group_count=len(groups),
                      events_without_group=int(result.group_id.isna().sum()), ML_used=False,
                      labels_used=False, severity_policy=policy)
        report["timings_seconds"]["pipeline_total"] = time.perf_counter()-started
        result.attrs["detection_schema_version"] = "spedia.detected.v1"
        result.attrs["pipeline_report"] = copy.deepcopy(report)
        return {"status": "success", "detected_logs": result, "atomic_alerts": atomic,
                "alerts": alerts, "alert_table": table, "groups": groups, "report": report}
    except (ValueError, TypeError, KeyError) as error:
        report.update(status="error", error=str(error))
        report["timings_seconds"]["pipeline_total"] = time.perf_counter()-started
        raise PipelineError(f"Pipeline failed at {report['stage']}: {error}", report) from error
