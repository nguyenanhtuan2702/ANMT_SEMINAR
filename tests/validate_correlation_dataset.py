"""Task 6 audit: vectorized groups vs an independent sequential reference.

python tests/validate_correlation_dataset.py --input dataset_log/logs_SPEDIA_annotated_en.csv
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection.alert_aggregation import merge_alerts
from detection.correlation import DEFAULT_CONFIG, correlate, get_timeline
from detection.rule_engine import DEFAULT_CONFIG as RULE_CONFIG, detect_rules
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize_logs


def records(frame: pd.DataFrame) -> list[dict]:
    return json.loads(frame.to_json(orient="records", date_format="iso", date_unit="ms", force_ascii=False))


def memberships(groups: pd.DataFrame) -> dict:
    links = groups[["group_id", "source_row_ids"]].explode("source_row_ids")
    assert not links.source_row_ids.duplicated().any()
    return dict(zip(links.source_row_ids, links.group_id))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/event_correlation"))
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve() or args.input.resolve().parent == args.output.resolve():
        raise ValueError("Output must differ from the dataset source.")
    source_hash = hashlib.sha256(args.input.read_bytes()).hexdigest()
    rules_hash = hashlib.sha256(RULE_CONFIG.read_bytes()).hexdigest()
    events = normalize_logs(load_logs(args.input))
    assert len(events) == 72250
    before = events.copy(deep=True)
    alerts = detect_rules(events.drop(columns="Anomaly", errors="ignore"))
    merged_alerts = merge_alerts(alerts)
    timings = []
    for _ in range(3):
        run = {}
        groups = correlate(events, merged_alerts, config=DEFAULT_CONFIG, report=run)
        timings.append(run["elapsed_seconds"])
    actual = memberships(groups)
    # A row loop is used ONLY in the independent audit, not in correlation.py.
    state, expected = {}, {}
    ordered = events.sort_values(["Timestamp", "record_index"], kind="stable")
    namespace = f"corr:v1:w{DEFAULT_CONFIG['window_seconds']}:g{DEFAULT_CONFIG['max_gap_seconds']}:"
    for timestamp, user, agent, sid, invalid in ordered[["Timestamp", "User", "Agent_name", "source_row_id", "invalid_timestamp"]].itertuples(index=False, name=None):
        if invalid or pd.isna(timestamp) or pd.isna(user) or not str(user).strip() or pd.isna(agent) or not str(agent).strip():
            continue
        bucket = timestamp.value//(DEFAULT_CONFIG["window_seconds"]*1_000_000_000)
        key = (user, agent, bucket)
        previous = state.get(key)
        first = sid if previous is None or (timestamp-previous[0]).total_seconds() > DEFAULT_CONFIG["max_gap_seconds"] else previous[1]
        state[key] = (timestamp, first)
        expected[sid] = namespace+first
    assert actual == expected
    assert groups.event_count.sum() == len(actual) == 70878
    assert len(groups.group_id.unique()) == len(groups)
    assert groups.alert_count.sum() == len(set(actual).intersection(a["source_row_id"] for a in alerts))
    assert groups.rule_match_count.sum() == len({(a["source_row_id"], a["rule_id"]) for a in alerts if a["source_row_id"] in actual})
    pd.testing.assert_frame_equal(groups, correlate(events, alerts, config=DEFAULT_CONFIG))
    pd.testing.assert_frame_equal(groups, correlate(events.drop(columns="Anomaly", errors="ignore"), merged_alerts, config=DEFAULT_CONFIG))
    # Use a real-data prefix around an auth group if available, so temporal
    # invariance includes nonzero auth alerts rather than only stateless rules.
    auth_ids = {a["source_row_id"] for a in alerts if a["rule_id"] == "AUTH_FAILURE_WINDOW"}
    auth_positions = events.index[events.source_row_id.isin(auth_ids)]
    prefix_count = int(auth_positions[0])+1 if len(auth_positions) else len(events)//2
    prefix = events.iloc[:prefix_count]
    point = (prefix.Timestamp.iloc[-1], int(prefix.record_index.iloc[-1]))
    prefix_ids = set(prefix.source_row_id)
    prefix_alerts = [a for a in alerts if a["source_row_id"] in prefix_ids]
    past = correlate(prefix, prefix_alerts, config=DEFAULT_CONFIG, as_of=point)
    same_snapshot = correlate(events, alerts, config=DEFAULT_CONFIG, as_of=point)
    pd.testing.assert_frame_equal(past, same_snapshot)
    past_members = memberships(past)
    assert past_members == {sid: actual[sid] for sid in past_members}
    selected = []
    for code, rule, text in (
        ("auth_cluster", "AUTH_FAILURE_WINDOW", "Authentication failure cluster with an identified user; timeline shows failures and activity for the same user/agent. Brute force is not confirmed."),
        ("configuration_context", "FILE_CONFIG_CHANGE", "Configuration changes within a working session. Task 5 shows file alerts may reflect legitimate activity; this group is not classified as an attack."),
        ("security_tool_context", "CMD_JOHN", "Password-testing tool within the same user/agent activity context; inspect argv and authorization; impact is not verified."),
    ):
        candidates = groups.loc[groups.rule_ids.map(lambda ids: rule in ids) & ~groups.group_id.isin([g["group"]["group_id"] for g in selected])].copy()
        if candidates.empty:
            continue
        candidates["_distance"] = (candidates.event_count-12).abs()
        choice = candidates.sort_values(["_distance", "start_time"]).iloc[0]
        timeline = get_timeline(events, choice.group_id, merged_alerts, config=DEFAULT_CONFIG)
        original = events.set_index("source_row_id").loc[timeline.source_row_id]
        for column in ("Full_log", "Description", "Content"):
            assert timeline[column].tolist() == original[column].tolist()
        assert timeline.source_row_id.tolist() == choice.source_row_ids
        assert timeline.has_alert.sum() == choice.alert_count
        assert "Anomaly" not in timeline
        # Validate the example timeline's frozen past snapshot as well.
        example_point = (timeline.Timestamp.iloc[-1], int(timeline.record_index.iloc[-1]))
        frozen = get_timeline(events, choice.group_id, merged_alerts, config=DEFAULT_CONFIG, as_of=example_point)
        pd.testing.assert_frame_equal(timeline, frozen)
        group_record = records(pd.DataFrame([choice.drop(labels=["_distance"])]))[0]
        selected.append({"example_id": code, "description": text, "group": group_record,
                         "as_of": {"timestamp": str(example_point[0]), "record_index": example_point[1]},
                         "timeline_file": f"timeline_{code}.csv"})
        args.output.mkdir(parents=True, exist_ok=True)
        timeline = timeline.copy()
        timeline["rule_ids"] = timeline.rule_ids.map(lambda value: json.dumps(value, ensure_ascii=False))
        timeline.to_csv(args.output/f"timeline_{code}.csv", index=False, encoding="utf-8-sig")
    assert len(selected) == 3
    pd.testing.assert_frame_equal(events, before)
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == source_hash
    assert hashlib.sha256(RULE_CONFIG.read_bytes()).hexdigest() == rules_hash
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(args.output/"groups.json", records(groups))
    table = groups.copy()
    for column in ("key", "activities", "rule_ids", "source_row_ids"):
        table[column] = table[column].map(lambda value: json.dumps(value, ensure_ascii=False))
    table.to_csv(args.output/"groups.csv", index=False, encoding="utf-8-sig")
    write_json(args.output/"examples.json", selected)
    summary = {
        "python_version": platform.python_version(), "pandas_version": pd.__version__,
        "source_sha256": source_hash, "rules_sha256": rules_hash,
        "correlation_report": run, "group_count": len(groups),
        "grouped_alert_events": int(groups.alert_count.sum()), "grouped_rule_matches": int(groups.rule_match_count.sum()),
        "timings_seconds": timings, "median_seconds": statistics.median(timings),
        "timing_scope": "correlate including validation and group aggregation, excludes load/normalize/rules/timeline/export",
        "historical_as_of": {"timestamp": str(point[0]), "record_index": point[1]},
        "checks": {"independent_sequential_reference_matches": True, "old_membership_ids_unchanged": True,
                   "same_as_of_snapshot_unchanged": True, "atomic_and_merged_inputs_equal": True,
                   "label_independent": True, "all_grouped_event_ids_unique": True,
                   "raw_timeline_evidence_preserved": True, "input_source_and_rule_config_unchanged": True},
    }
    write_json(args.output/"correlation_validation.json", summary)
    print(json.dumps(summary, indent=2))
    print(json.dumps([{k: item[k] for k in ("example_id", "description", "group")} for item in selected], ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
