"""Audit and benchmark rules on a local full dataset; never use labels for rules.

python tests/validate_rule_engine_dataset.py --input dataset_log/logs_SPEDIA_annotated_en.csv
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path
import platform
import re
import statistics
import sys

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection.rule_engine import ALERT_COLUMNS, alerts_to_dataframe, detect_rules, load_rule_config
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize_logs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/rule_detection"))
    parser.add_argument("--expected-rows", type=int, default=72250)
    args = parser.parse_args()
    if any((args.output/name).resolve() == args.input.resolve() for name in
           ("alerts.csv", "alert_examples.json", "rule_engine_validation.json")):
        raise ValueError("Audit output must not overwrite the source dataset")
    digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    config = load_rule_config()
    events = normalize_logs(load_logs(args.input))
    assert len(events) == args.expected_rows
    baseline = events.copy(deep=True)
    timings = []
    for _ in range(3):
        run = {}
        current = detect_rules(events, config=config, report=run)
        timings.append(run["elapsed_seconds"])
        if not timings[:-1]:
            alerts = current
        else:
            assert alerts == current
    without_labels = detect_rules(events.drop(columns=["Anomaly", "Level"], errors="ignore"), config=config)
    assert alerts == without_labels
    # Independent deque implementation checks the rolling algorithm, group keys,
    # closed left boundary and causal current/past-only count on real failures.
    auth = next(r for r in config["rules"] if r["rule_id"] == "AUTH_FAILURE_WINDOW")
    params = auth["params"]
    pattern = re.compile(params["failure_regex"], re.IGNORECASE)
    windows = defaultdict(deque)
    expected_auth = {}
    for timestamp, user, agent, action, description, full_log, sid in events[
        ["Timestamp", "User", "Agent_name", "Action", "Description", "Full_log", "source_row_id"]
    ].itertuples(index=False, name=None):
        failure = (action in params["failure_actions"] or any(
            isinstance(value, str) and pattern.search(value) for value in (action, description, full_log)
        ))
        if not failure or pd.isna(timestamp) or pd.isna(user) or not str(user).strip():
            continue
        queue = windows[(user, agent)]
        left = timestamp - pd.Timedelta(seconds=params["window_seconds"])
        while queue and queue[0] < left:
            queue.popleft()
        queue.append(timestamp)
        if len(queue) >= params["threshold"]:
            expected_auth[sid] = len(queue)
    actual_auth = {a["source_row_id"]: int(a["evidence"]["count"]) for a in alerts if a["rule_id"] == auth["rule_id"]}
    assert actual_auth == expected_auth
    prefix = events.iloc[:len(events)//3]
    prefix_ids = set(prefix.source_row_id)
    prefix_alerts = detect_rules(prefix, config=config)
    assert prefix_alerts == [a for a in alerts if a["source_row_id"] in prefix_ids]
    counts = dict(Counter(a["rule_id"] for a in alerts))
    # Task 1 masks, with explicit Action checks, match these observed defaults.
    for rid, expected in {"CMD_NMAP": 47, "CMD_JOHN": 185, "CMD_MSFCONSOLE": 105,
                          "HTTP_IP_HOST": 105}.items():
        assert counts.get(rid, 0) == expected, (rid, counts.get(rid))
    file_params = next(r for r in config["rules"] if r["rule_id"] == "FILE_CONFIG_CHANGE")["params"]
    file_mask = events.Path.str.contains(file_params["path_regex"], regex=True, na=False) & events.Action.isin(file_params["actions"])
    if "exclude_modified_raw_regex" in file_params:
        file_mask &= ~(events.Action.eq("file modified") & events.Full_log.str.contains(file_params["exclude_modified_raw_regex"], case=False, regex=True, na=False))
    assert counts.get("FILE_CONFIG_CHANGE", 0) == int(file_mask.sum())
    assert len(counts) >= 3
    assert len({a["alert_id"] for a in alerts}) == len(alerts)
    originals = events.set_index("source_row_id")[["Full_log", "Description", "Content"]].to_dict("index")
    for alert in alerts:
        assert set(alert) == set(ALERT_COLUMNS)
        assert alert["reason"] and alert["severity_reason"]
        assert "Anomaly" not in alert["evidence"] and "Level" not in alert["evidence"]
        for field in ("Full_log", "Description", "Content"):
            original = originals[alert["source_row_id"]][field]
            assert alert["evidence"][field] == (None if pd.isna(original) else original)
    pd.testing.assert_frame_equal(events, baseline)
    assert events.attrs == baseline.attrs
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == digest
    args.output.mkdir(parents=True, exist_ok=True)
    table = alerts_to_dataframe(alerts)
    table["evidence"] = table["evidence"].map(lambda value: json.dumps(value, ensure_ascii=False))
    table.to_csv(args.output/"alerts.csv", index=False, encoding="utf-8-sig")
    examples = {rid: [a for a in alerts if a["rule_id"] == rid][:2] for rid in counts}
    (args.output/"alert_examples.json").write_text(json.dumps(examples, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    result = {
        "source": args.input.as_posix(), "source_sha256": digest,
        "python_version": platform.python_version(), "pandas_version": pd.__version__,
        "rows": len(events), "alert_count": len(alerts), "counts_by_rule": counts,
        "rule_engine_seconds": timings, "median_rule_engine_seconds": statistics.median(timings),
        "timing_scope": "detect_rules only, including validation/masks/windows/serialization; excludes CSV load, normalization and exports",
        "run_report": run,
        "config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        "checks": {"label_and_Level_independent": True, "independent_deque_matches_auth": True,
                   "future_suffix_does_not_change_prefix_alerts": True, "raw_evidence_preserved": True,
                   "alert_contract_and_unique_ids": True, "task1_counts_confirmed": True,
                   "input_and_source_unchanged": True, "three_runs_deterministic": True},
    }
    (args.output/"rule_engine_validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
