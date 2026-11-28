"""Full upload/pipeline/export/UI audit. Run from repo root with .venv Python."""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import platform
import time

import pandas as pd

from dashboard.service import run_upload_pipeline
from detection.pipeline import DETECTION_COLUMNS, run_detection_pipeline
from preprocessing.detected_io import save_detected_logs, read_detected_logs


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dataset_log/logs_SPEDIA_annotated_en.csv"))
    parser.add_argument("--output", type=Path, default=Path("data/detected_logs.csv"))
    parser.add_argument("--check-dashboard", action="store_true")
    args = parser.parse_args()
    protected = [args.input, Path("data/normalized_logs.csv"), Path("data/alerts.csv"), Path("data/event_groups.csv"),
                 Path("detection/rules.json"), Path("docs/schemas/alert_v1.0.schema.json"), Path("docs/schemas/alert_v1.0.freeze.json")]
    if args.output.resolve() in {p.resolve() for p in protected}:
        raise ValueError("Refusing to overwrite input/frozen artifacts.")
    hashes = {str(p): digest(p) for p in protected if p.exists()}
    raw = args.input.read_bytes()
    result = run_upload_pipeline(BytesIO(raw))
    detected = result["detected_logs"]
    timings = result["report"]["timings_seconds"].copy()
    normalized = detected.drop(columns=list(DETECTION_COLUMNS))
    normalized.attrs.pop("detection_schema_version", None)
    normalized.attrs.pop("pipeline_report", None)
    source = pd.read_csv(BytesIO(raw), dtype="string", keep_default_na=False)
    for column in ("Full_log", "Description", "Content"):
        pd.testing.assert_series_equal(
            detected[column].reset_index(drop=True),
            source.iloc[detected.record_index.to_numpy(dtype="int64")][column].reset_index(drop=True))
    source_hash = hashlib.sha256(raw).hexdigest()
    assert detected.source_row_id.tolist() == [source_hash+f":{int(i):08d}" for i in detected.record_index]
    # Same features and detections with no label/Level at all.
    label_free = run_detection_pipeline(normalized.drop(columns=["Anomaly", "Level"], errors="ignore"))
    pd.testing.assert_frame_equal(detected[list(DETECTION_COLUMNS)], label_free["detected_logs"][list(DETECTION_COLUMNS)])
    assert result["alerts"] == label_free["alerts"]
    snapshots = []
    for fraction in [.25, .5, .75]:
        anchor = normalized.iloc[int(len(normalized)*fraction)]
        mask = normalized.Timestamp.lt(anchor.Timestamp) | (normalized.Timestamp.eq(anchor.Timestamp) & normalized.record_index.le(anchor.record_index))
        early = run_detection_pipeline(normalized.loc[mask])
        pd.testing.assert_frame_equal(early["detected_logs"][list(DETECTION_COLUMNS)], detected.loc[mask, list(DETECTION_COLUMNS)])
        snapshots.append({"timestamp": anchor.Timestamp.isoformat(), "record_index": int(anchor.record_index), "rows_checked": int(mask.sum())})
    step = time.perf_counter()
    meta = save_detected_logs(detected, args.output)
    timings["export_csv"] = time.perf_counter()-step
    step = time.perf_counter()
    restored = read_detected_logs(args.output)
    timings["read_detected_csv"] = time.perf_counter()-step
    pd.testing.assert_frame_equal(detected, restored, check_exact=True)
    assert detected.attrs == restored.attrs
    ui = {"executed": False}
    if args.check_dashboard:
        import streamlit
        from streamlit.testing.v1 import AppTest
        step = time.perf_counter()
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1]/"dashboard/app.py"), default_timeout=180).run()
        assert not app.exception and not app.success
        app.file_uploader[0].set_value((args.input.name, raw, "text/csv")).run(timeout=180)
        assert not app.exception and not app.error and app.success
        assert app.metric[0].value == f"{len(detected):,}" and app.metric[1].value == f"{len(result['alerts']):,}"
        assert len(app.selectbox) == 2  # alert evidence and timeline both rendered
        cold_ui = time.perf_counter()-step
        step = time.perf_counter()
        app.multiselect[0].set_value(["command"]).run(timeout=180)
        assert not app.exception and not app.error
        timings.update(dashboard_initial_upload=cold_ui, dashboard_cached_filter_rerun=time.perf_counter()-step)
        ui = {"executed": True, "streamlit_version": streamlit.__version__, "upload_widget": True,
              "overview_alerts_timeline_rendered": True, "filter_rerun_ok": True, "human_Tuan_review": "pending"}
    assert all(digest(k) == v for k, v in hashes.items())
    folder = Path("reports/pipeline_integration")
    folder.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(list(timings.items()), columns=["step", "seconds"]).to_csv(folder/"timings.csv", index=False)
    report = {"python_version": platform.python_version(), "pandas_version": pd.__version__,
              "rows": len(detected), "columns": len(detected.columns), "atomic_alerts": len(result["atomic_alerts"]),
              "alerted_events": len(result["alerts"]), "groups": len(result["groups"]),
              "events_without_group": int(detected.group_id.isna().sum()),
              "severity_counts": detected.severity.value_counts().to_dict(),
              "no_alert_severity_null": int(detected.severity.isna().sum()),
              "timings_seconds": timings, "snapshots": snapshots, "dashboard": ui,
              "output": {"csv": str(args.output), "csv_sha256": meta["csv_sha256"], "bytes": args.output.stat().st_size},
              "protected_inputs_sha256": hashes,
              "checks": {"CSV_round_trip_exact": True, "label_Level_independent": True,
                         "future_features_unchanged_at_3_cutoffs": True, "frozen_inputs_unchanged": True,
                         "raw_fields_and_source_keys_preserved": True},
              "pipeline_report": result["report"]}
    (folder/"pipeline_validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("rows", "columns", "alerted_events", "groups", "timings_seconds", "dashboard", "checks")}, indent=2))


if __name__ == "__main__":
    main()
