"""Finalize Task 9 statistics/charts after pytest passes, without rewriting data.

Run from repo root: python tests/validate_task9_dataset.py --check-dashboard
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Keep plotting caches in the permitted temporary directory, outside the report.
_plot_cache = tempfile.TemporaryDirectory(prefix="anmt_task9_plot_")
os.environ.setdefault("MPLCONFIGDIR", _plot_cache.name)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from dashboard.service import run_upload_pipeline
from data_for_ml.load_data import load_table, verify_bundle
from detection.rule_engine import load_rule_config


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2)+"\n").encode("utf-8"))


def semantic_digest(result):
    payload = {"atomic": result["atomic_alerts"], "alerts": result["alerts"],
               "groups": json.loads(result["groups"].to_json(orient="records", date_format="iso", date_unit="ns")),
               "logs": json.loads(result["detected_logs"].to_json(orient="records", date_format="iso", date_unit="ns"))}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def pytest_results(folder):
    path = folder/"pytest_final.xml"
    if not path.is_file():
        raise ValueError("Run the full pytest suite with --junitxml=reports/testing_optimization/pytest_final.xml first.")
    root = ET.parse(path).getroot()
    cases = []
    for case in root.iter("testcase"):
        state, message = "passed", ""
        for tag in ("failure", "error", "skipped"):
            child = case.find(tag)
            if child is not None:
                state, message = tag, child.get("message", "")
                break
        cases.append({"case": case.get("name"), "module": case.get("classname"),
                      "status": state, "seconds": float(case.get("time", 0)), "message": message})
    counts = dict(Counter(c["status"] for c in cases))
    if not cases or counts.get("failure", 0) or counts.get("error", 0) or counts.get("skipped", 0):
        raise ValueError(f"The full local pytest suite must pass without skipped tests: {counts}")
    pd.DataFrame(cases).to_csv(folder/"test_cases.csv", index=False, encoding="utf-8-sig")
    suites = list(root.iter("testsuite"))
    summary = {"cases": len(cases), "counts": counts,
               "subtests_passed": sum(int(s.get("tests", 0)) for s in suites)-len(cases),
               "suite_seconds": sum(float(s.get("time", 0)) for s in suites),
               "junit_sha256": digest(path)}
    write_json(folder/"test_summary.json", summary)
    return summary


def charts(folder, rules, severity, distribution):
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})
    figures = []
    specs = [
        ("alerts_by_rule", rules.rule_id.tolist(), rules.alert_count.tolist(),
         "Alerts by rule (disabled rule is zero)", "Alert records", "#386cb0"),
        ("alerts_by_severity", severity.severity.tolist(), severity.event_count.tolist(),
         "Prototype processing priority, not verified impact", "Alerted events", ["#66a61e", "#e6ab02", "#e66101", "#b2182b"]),
        ("correlation_group_sizes", distribution.event_count_range.tolist(), distribution.group_count.tolist(),
         "Correlation group size distribution", "Groups", "#1b9e77"),
    ]
    for stem, labels, values, title, ylabel, color in specs:
        fig, ax = plt.subplots(figsize=(10, 5.5))
        bars = ax.bar(labels, values, color=color)
        ax.bar_label(bars, padding=3, fontsize=9)
        ax.set(title=title, ylabel=ylabel)
        ax.set_ylim(0, max(values)*1.2 if max(values) else 1)
        if stem == "alerts_by_rule":
            plt.setp(ax.get_xticklabels(), rotation=25, ha="right")
        else:
            ax.set_xlabel("Priority" if stem == "alerts_by_severity" else "Events per group")
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        for extension in ("png", "svg"):
            path = folder/(stem+"."+extension)
            fig.savefig(path, dpi=180, metadata={"Description": "Task 9 final rule-based SPEDIA statistics"})
            figures.append(path.name)
        plt.close(fig)
    return figures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-dashboard", action="store_true")
    args = parser.parse_args()
    folder = Path("reports/testing_optimization")
    folder.mkdir(parents=True, exist_ok=True)
    tests = pytest_results(folder)
    verify_bundle()
    protected = [Path("data/raw/logs_SPEDIA_annotated_en.csv"), Path("detection/rules.json"),
                 Path("detection/severity_policy.json"), Path("docs/schemas/alert_v1.0.schema.json"),
                 Path("docs/schemas/alert_v1.0.freeze.json")]
    for root in (Path("data"), Path("data_for_ml"), Path("models/artifacts")):
        protected.extend(p for p in root.iterdir() if p.is_file())
    hashes = {p.as_posix(): digest(p) for p in protected}
    raw = Path("data/raw/logs_SPEDIA_annotated_en.csv").read_bytes()
    runs, elapsed = [], []
    for _ in range(2):
        started = time.perf_counter()
        runs.append(run_upload_pipeline(BytesIO(raw)))
        elapsed.append(time.perf_counter()-started)
    first, second = runs
    assert first["atomic_alerts"] == second["atomic_alerts"] and first["alerts"] == second["alerts"]
    for key in ("groups", "alert_table", "detected_logs"):
        pd.testing.assert_frame_equal(first[key], second[key], check_exact=True)
    signature = semantic_digest(first)
    assert signature == semantic_digest(second)
    logs, groups = first["detected_logs"], first["groups"]
    frozen = load_table("detected_logs.csv")
    pd.testing.assert_frame_equal(groups, load_table("event_groups.csv"), check_exact=True)
    for column in ("source_row_id", "record_index", "rule_ids", "alert_count", "group_id", "severity", "Full_log", "Description", "Content"):
        pd.testing.assert_series_equal(logs[column], frozen[column], check_exact=True)
    assert len(logs) == 72250 and len(first["alerts"]) == 1301 and len(groups) == 7501
    raw_frame = pd.read_csv(BytesIO(raw), dtype="string", keep_default_na=False)
    for column in ("Full_log", "Description", "Content"):
        pd.testing.assert_series_equal(logs[column], raw_frame.iloc[logs.record_index.to_numpy(dtype="int64")][column].reset_index(drop=True), check_exact=True)
    rule_counts = Counter(a["rule_id"] for a in first["atomic_alerts"])
    rule_table = pd.DataFrame([{"rule_id": r["rule_id"], "enabled": r["enabled"], "base_severity": r["base_severity"],
                                "alert_count": rule_counts.get(r["rule_id"], 0)} for r in load_rule_config()["rules"]])
    severity_counts = Counter(a["severity"] for a in first["alerts"])
    severity_table = pd.DataFrame([{"severity": s, "event_count": severity_counts.get(s, 0)} for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")])
    ranges = ["1", "2-5", "6-10", "11-20", "21-50", "51+"]
    bins = pd.cut(groups.event_count.astype("int64"), [0, 1, 5, 10, 20, 50, float("inf")], labels=ranges)
    distribution = pd.DataFrame({"event_count_range": ranges, "group_count": bins.value_counts(sort=False).reindex(ranges, fill_value=0).to_numpy()})
    group_summary = {"groups": len(groups), "grouped_events": int(groups.event_count.sum()),
                     "ungrouped_events": int(logs.group_id.isna().sum()),
                     "grouped_alert_events": int(groups.alert_count.sum()),
                     "ungrouped_alert_events": int((logs.alert_count.gt(0)&logs.group_id.isna()).sum()),
                     "singleton_groups": int(groups.event_count.eq(1).sum()), "max_group_size": int(groups.event_count.max())}
    rule_table.to_csv(folder/"alerts_by_rule.csv", index=False)
    severity_table.to_csv(folder/"alerts_by_severity.csv", index=False)
    distribution.to_csv(folder/"correlation_group_sizes.csv", index=False)
    pd.DataFrame(list(group_summary.items()), columns=["metric", "value"]).to_csv(folder/"correlation_summary.csv", index=False)
    timing_rows = [{"run": i+1, "step": key, "seconds": value} for i, run in enumerate(runs) for key, value in run["report"]["timings_seconds"].items()]
    pd.DataFrame(timing_rows).to_csv(folder/"timings.csv", index=False)
    figure_names = charts(folder, rule_table, severity_table, distribution)
    dashboard = {"executed": False}
    if args.check_dashboard:
        import streamlit
        from streamlit.testing.v1 import AppTest
        started = time.perf_counter()
        app = AppTest.from_file(str(Path("dashboard/app.py").resolve()), default_timeout=180).run()
        app.file_uploader[0].set_value(("logs.csv", raw, "text/csv")).run(timeout=180)
        assert not app.exception and not app.error and app.success
        assert app.metric[0].value == "72,250" and app.metric[1].value == "1,301" and app.metric[2].value == "7,501"
        assert len(app.selectbox) == 2
        cold_seconds = time.perf_counter()-started
        started = time.perf_counter()
        app.multiselect[0].set_value(["command"]).run(timeout=180)
        assert not app.exception and not app.error
        dashboard = {"executed": True, "streamlit_version": streamlit.__version__, "rows": len(logs),
                     "upload_alerts_timeline_ok": True, "filter_rerun_ok": True,
                     "cold_seconds": cold_seconds, "cached_filter_seconds": time.perf_counter()-started}
    assert all(digest(path) == expected for path, expected in hashes.items())
    summary = {"status": "passed", "scope": "Task 9 rule-based finalization; ML not included in severity",
               "python_version": platform.python_version(), "pandas_version": pd.__version__, "pytest": tests,
               "source_rows": len(logs), "source_columns": 24, "detected_columns": len(logs.columns),
               "atomic_alerts": len(first["atomic_alerts"]), "alerted_events": len(first["alerts"]),
               "events_without_alert": int(logs.alert_count.eq(0).sum()),
               "alerts_by_rule": dict(rule_counts), "alerts_by_severity": dict(severity_counts),
               "correlation": group_summary, "reproducibility": {"runs": 2, "semantic_sha256": signature,
               "exact_semantic_outputs_equal": True, "timings_excluded_from_equality": True, "wall_seconds": elapsed},
               "checks": {"frozen_detected_features_match": True, "all_group_metadata_and_membership_match_frozen_table": True,
                          "raw_fields_equal_original_CSV": True,
                          "data_bundle_source_models_rules_and_schema_unchanged": True},
               "dashboard": dashboard, "figures": figure_names, "protected_files_sha256": hashes}
    write_json(folder/"final_summary.json", summary)
    import subprocess
    environment = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, check=True).stdout
    (folder/"environment.txt").write_bytes(environment)
    print(json.dumps({key: summary[key] for key in ("status", "source_rows", "atomic_alerts", "alerts_by_rule", "alerts_by_severity", "correlation", "pytest", "dashboard")}, indent=2))


if __name__ == "__main__":
    main()
