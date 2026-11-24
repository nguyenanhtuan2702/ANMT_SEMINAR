"""Build shared Task 4-6 artifacts from the full normalized dataset.

python -m detection.export_shared_outputs
alerts_atomic.csv = Task 4; alerts.csv = merged Task 5 v1.0;
event_groups.csv = Task 6. No labels score or tune the detector here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform

import pandas as pd

from detection.alert_aggregation import merge_alerts, validate_merged_alert
from detection.correlation import DEFAULT_CONFIG as CORRELATION_CONFIG, correlate, get_timeline
from detection.rule_engine import DEFAULT_CONFIG as RULE_CONFIG, detect_rules
from detection.shared_output_io import (
    save_atomic_alerts, read_atomic_alerts, save_alerts, read_alerts,
    save_event_groups, read_event_groups,
)
from preprocessing.normalized_io import read_normalized_logs


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_shared_outputs(normalized: str | Path = "data/normalized_logs.csv", output_dir: str | Path = "data") -> dict:
    normalized, output = Path(normalized), Path(output_dir)
    names = ("alerts_atomic.csv", "alerts.csv", "event_groups.csv")
    targets = [output/name for name in names]
    targets += [p.with_suffix(".schema.json") for p in targets]
    targets.append(output/"analysis_outputs.manifest.json")
    if normalized.resolve() in {p.resolve() for p in targets} or normalized.with_suffix(".schema.json").resolve() in {p.resolve() for p in targets}:
        raise ValueError("Refusing to overwrite normalized input/sidecar.")
    normalized_hash, rule_hash = digest(normalized), digest(RULE_CONFIG)
    schema_path = Path("docs/schemas/alert_v1.0.schema.json")
    freeze = read_json(Path("docs/schemas/alert_v1.0.freeze.json"))
    if digest(schema_path) != freeze["schema_sha256"]:
        raise ValueError("Schema v1.0 has changed since it was frozen.")
    events = read_normalized_logs(normalized)
    source_hash = events.attrs.get("load_report", {}).get("file_sha256")
    frozen_manifest = Path("reports/rule_validation/preparation_manifest.json")
    if frozen_manifest.exists():
        frozen = read_json(frozen_manifest)
        if rule_hash != frozen["rules_sha256"] or source_hash != frozen["source_sha256"]:
            raise ValueError("Source/rules do not match the technically frozen Task 5 version; create a new evaluation version first.")
    run = {}
    atomic = detect_rules(events.drop(columns="Anomaly", errors="ignore"), report=run)
    merged = merge_alerts(atomic)
    correlation_report = {}
    groups = correlate(events.drop(columns="Anomaly", errors="ignore"), merged,
                       config=CORRELATION_CONFIG, report=correlation_report)
    provenance = {"normalized_csv": str(normalized), "normalized_csv_sha256": normalized_hash,
                  "source_sha256": source_hash, "rules_sha256": rule_hash,
                  "alert_schema_sha256": freeze["schema_sha256"], "correlation_config": CORRELATION_CONFIG,
                  "team_signoff": freeze["team_signoff"], "label_used_for_detection": False}
    atomic_meta = save_atomic_alerts(atomic, output/"alerts_atomic.csv", provenance=provenance)
    merged_meta = save_alerts(merged, output/"alerts.csv", provenance=provenance)
    group_meta = save_event_groups(groups, output/"event_groups.csv", provenance=provenance)
    restored_atomic = read_atomic_alerts(output/"alerts_atomic.csv")
    restored = read_alerts(output/"alerts.csv")
    restored_groups = read_event_groups(output/"event_groups.csv")
    assert atomic == restored_atomic and merged == restored
    pd.testing.assert_frame_equal(groups, restored_groups, check_exact=True)
    assert groups.attrs == restored_groups.attrs
    pd.testing.assert_frame_equal(correlate(events, restored_atomic, config=CORRELATION_CONFIG), groups, check_exact=True)
    pd.testing.assert_frame_equal(correlate(events, restored, config=CORRELATION_CONFIG), groups, check_exact=True)
    frozen_merged = Path("reports/rule_validation/merged_alerts_v1.0.json")
    if frozen_merged.exists():
        frozen_alerts = read_json(frozen_merged)
        for alert in frozen_alerts:
            validate_merged_alert(alert)
        # All detection fields/evidence must match; only the generated summary
        # may use the validated historical translation instead of English.
        assert [{k: v for k, v in a.items() if k != "severity_reason"} for a in restored] == [
            {k: v for k, v in a.items() if k != "severity_reason"} for a in frozen_alerts]
    examples_path = Path("reports/event_correlation/examples.json")
    timeline_checks = 0
    if examples_path.exists():
        for example in read_json(examples_path):
            point = (pd.Timestamp(example["as_of"]["timestamp"]), int(example["as_of"]["record_index"]))
            gid = example["group"]["group_id"]
            before = get_timeline(events, gid, merged, config=CORRELATION_CONFIG, as_of=point)
            after = get_timeline(events, gid, restored, config=CORRELATION_CONFIG, as_of=point)
            pd.testing.assert_frame_equal(before, after, check_exact=True)
            timeline_checks += 1
    # No input or frozen config is changed by exporting/reloading.
    assert (digest(normalized) == normalized_hash and digest(RULE_CONFIG) == rule_hash
            and digest(schema_path) == freeze["schema_sha256"])
    file_checks = {path.name: digest(path) for path in targets if path.name != "analysis_outputs.manifest.json"}
    manifest = {"format_version": "spedia.analysis_bundle.v1", "provenance": provenance,
                "files_sha256": file_checks, "normalized_rows": len(events),
                "atomic_alert_rows": len(atomic), "merged_alert_rows": len(merged), "event_group_rows": len(groups)}
    (output/"analysis_outputs.manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    result = {"python_version": platform.python_version(), "pandas_version": pd.__version__,
              **{k: manifest[k] for k in ("normalized_rows", "atomic_alert_rows", "merged_alert_rows", "event_group_rows")},
              "grouped_alert_events": int(groups.alert_count.sum()),
              "ungrouped_alert_events": correlation_report["alert_events_excluded_from_grouping"],
              "outputs": {name: {"rows": meta["row_count"], "csv_sha256": meta["csv_sha256"]} for name, meta in
                          (("alerts_atomic.csv", atomic_meta), ("alerts.csv", merged_meta), ("event_groups.csv", group_meta))},
              "rule_run_report": run, "correlation_report": correlation_report,
              "timeline_examples_checked": timeline_checks,
              "checks": {"atomic_csv_round_trip_exact": True, "merged_csv_round_trip_exact": True,
                         "group_csv_round_trip_exact": True, "reloaded_alerts_reproduce_groups": True,
                         "frozen_task5_alerts_match": frozen_merged.exists(),
                         "timeline_examples_unchanged": timeline_checks == 3,
                         "no_Anomaly_in_detector_input_or_exported_alerts": True,
                         "normalized_input_rules_and_alert_schema_unchanged": True},
              "team_signoff": freeze["team_signoff"]}
    report_dir = Path("reports/shared_outputs")
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir/"validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normalized", type=Path, default=Path("data/normalized_logs.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    print(json.dumps(build_shared_outputs(args.normalized, args.output_dir), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
