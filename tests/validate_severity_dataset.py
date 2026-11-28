"""Validate Task 7 against full normalized data, preserving frozen Task 4-6.

Run from repo root: python tests/validate_severity_dataset.py
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd

from detection.alert_aggregation import merge_alerts
from detection.correlation import correlate
from detection.severity import assign_severity, load_severity_config
from detection.shared_output_io import read_atomic_alerts, read_event_groups, save_atomic_alerts, save_alerts
from preprocessing.normalized_io import read_normalized_logs


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    paths = ["data/alerts.csv", "data/alerts_atomic.csv", "data/event_groups.csv", "data/normalized_logs.csv",
             "detection/rules.json", "docs/schemas/alert_v1.0.schema.json", "docs/schemas/alert_v1.0.freeze.json"]
    frozen = {name: digest(name) for name in paths}
    events = read_normalized_logs("data/normalized_logs.csv")
    alerts, groups = read_atomic_alerts(), read_event_groups()
    original = copy.deepcopy(alerts)
    config = load_severity_config()
    started = time.perf_counter()
    scored = assign_severity(alerts, groups, events=events)
    elapsed = time.perf_counter()-started
    assert alerts == original
    for before, after in zip(alerts, scored):
        assert {k: v for k, v in before.items() if k not in {"severity", "severity_reason"}} == {
            k: v for k, v in after.items() if k not in {"severity", "severity_reason"}}
    assert assign_severity(scored, groups, events=events) == scored
    # Removing labels/Level entirely must reproduce identical priorities/reasons.
    assert assign_severity(alerts, groups, events=events.drop(columns=["Anomaly", "Level"], errors="ignore")) == scored
    assert assign_severity(alerts, groups, ml_results={"anomaly_score": "ignored"}, events=events) == scored
    # Three chronological cutoffs, including ties bounded by original row index.
    snapshots = []
    source_indices = dict(zip(events.source_row_id, events.record_index))
    for position in [len(alerts)//4, len(alerts)//2, 3*len(alerts)//4]:
        anchor = alerts[position]
        stamp, index = pd.Timestamp(anchor["timestamp"]), int(source_indices[anchor["source_row_id"]])
        early_events = events.loc[events.Timestamp.lt(stamp) | (events.Timestamp.eq(stamp) & events.record_index.le(index))].copy()
        early_alerts = [a for a in alerts if (pd.Timestamp(a["timestamp"]), source_indices[a["source_row_id"]]) <= (stamp, index)]
        early_groups = correlate(early_events, [], config=config["correlation"])
        early_scored = assign_severity(early_alerts, early_groups, events=early_events)
        expected = {a["alert_id"]: a for a in scored}
        assert all(a == expected[a["alert_id"]] for a in early_scored)
        snapshots.append({"timestamp": anchor["timestamp"], "record_index": index, "alerts_checked": len(early_scored)})
    output = Path("reports/severity_assignment")
    output.mkdir(parents=True, exist_ok=True)
    provenance = {"policy_sha256": digest("detection/severity_policy.json"), "inputs_sha256": frozen,
                  "prototype_priority_only": True, "ML_used": False, "label_used": False}
    save_atomic_alerts(scored, output/"prioritized_atomic_alerts.csv", provenance=provenance)
    merged = merge_alerts(scored)
    save_alerts(merged, output/"prioritized_alerts_v1.0.csv", provenance=provenance)
    from detection.shared_output_io import read_alerts
    assert read_atomic_alerts(output/"prioritized_atomic_alerts.csv") == scored
    assert read_alerts(output/"prioritized_alerts_v1.0.csv") == merged
    summary = {"python_version": platform.python_version(), "pandas_version": pd.__version__,
               "rows_input": len(events), "atomic_alerts": len(scored), "merged_alert_events": len(merged),
               "elapsed_seconds": round(elapsed, 6),
               "severity_counts": pd.Series([a["severity"] for a in scored]).value_counts().to_dict(),
               "changed_from_base": sum(a["severity"] != b["severity"] for a, b in zip(scored, original)),
               "policy": config, "snapshots": snapshots, "provenance": provenance,
               "checks": {"frozen_inputs_unchanged": all(digest(k) == v for k, v in frozen.items()),
                          "raw_detection_reason_unchanged": True, "label_Level_independent": True,
                          "ML_ignored": True, "idempotent": True, "future_does_not_rescore_past": True,
                          "CSV_round_trip_exact": True}}
    assert all(summary["checks"].values())
    examples = {level: next((a for a in scored if a["severity"] == level), None)
                for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    (output/"examples.json").write_text(json.dumps(examples, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    (output/"severity_validation.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
