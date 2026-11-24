"""Task 5: label-blind sampling followed by separate reference-label scoring.

python -m evaluation.verify_rules --phase prepare
Review reports/rule_validation/review_samples_blind.json, save review_notes.json, then:
python -m evaluation.verify_rules --phase evaluate
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import platform
import re

import pandas as pd

from detection.alert_aggregation import merge_alerts, merged_alerts_to_dataframe
from detection.rule_engine import DEFAULT_CONFIG, detect_rules, load_rule_config
from evaluation.rule_metrics import evaluate_rule_alerts
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize_logs


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_samples(alerts: list[dict], rule_id: str, count: int = 25, seed: str = "20261121") -> list[dict]:
    """Fixed-size hash-ranked sampling, with no labels or agent-name strata."""
    by_id = {a["source_row_id"]: a for a in alerts if a["rule_id"] == rule_id}
    ranked = sorted(by_id, key=lambda sid: hashlib.sha256(f"{seed}|{rule_id}|{sid}".encode()).hexdigest())
    return [by_id[sid] for sid in ranked[:count]]


def prepare(source: Path, output: Path) -> None:
    if (output/"evaluation_summary.json").exists():
        raise ValueError("Evaluation is frozen; prepare a new version directory instead of overwriting it.")
    output.mkdir(parents=True, exist_ok=True)
    config = load_rule_config()
    events = normalize_logs(load_logs(source))
    events.attrs = {}
    # Anomaly remains absent from all detector and reviewer inputs.
    detector_events = events.drop(columns=["Anomaly"], errors="ignore")
    run = {}
    atomic = detect_rules(detector_events, config=config, report=run)
    active = [r["rule_id"] for r in config["rules"] if r["enabled"]]
    disabled = [r["rule_id"] for r in config["rules"] if not r["enabled"]]
    diagnostic = detect_rules(detector_events, config={**config, "enabled_rule_ids": disabled}) if disabled else []
    merged = merge_alerts(atomic)
    write_json(output/"atomic_alerts.json", atomic)
    write_json(output/"merged_alerts_v1.0.json", merged)
    table = merged_alerts_to_dataframe(merged)
    for column in ("rule_ids", "rule_matches"):
        table[column] = table[column].map(lambda x: json.dumps(x, ensure_ascii=False))
    table.to_csv(output/"merged_alerts_v1.0.csv", index=False, encoding="utf-8-sig")
    write_json(output/"diagnostic_disabled_alerts.json", diagnostic)
    write_json(output/"rules_frozen_v1.0.json", config)
    record_indices = dict(zip(events.source_row_id, events.record_index))
    chosen = []
    sample_counts = {}
    for rid in active+disabled:
        pool = atomic if rid in active else diagnostic
        selected = select_samples(pool, rid)
        sample_counts[rid] = {"mode": "production" if rid in active else "diagnostic_disabled",
                              "available": sum(a["rule_id"] == rid for a in pool), "selected": len(selected)}
        for alert in selected:
            chosen.append({"sample_id": rid+"|"+alert["source_row_id"], "rule_id": rid,
                           "mode": sample_counts[rid]["mode"], "source_row_id": alert["source_row_id"],
                           "record_index": int(record_indices[alert["source_row_id"]]), "alert": alert})
    targets = {s["record_index"] for s in chosen}
    raw = {}
    with source.open(encoding="utf-8-sig", newline="") as stream:
        for index, row in enumerate(csv.DictReader(stream)):
            if index in targets:
                raw[index] = {c: row.get(c, "") for c in
                              ("id", "Timestamp", "User", "Agent_name", "Activity", "Action", "Decoder_name", "Command", "Path", "Filename", "Url", "Description", "Full_log", "Content")}
    for sample in chosen:
        original = raw[sample["record_index"]]
        for column in ("Full_log", "Description", "Content"):
            assert sample["alert"]["evidence"][column] == original[column]
        sample["raw_source"] = original
        sample["raw_comparison"] = "exact_match_all_three_raw_fields"
        block = re.search(r"type=EXECVE\b(.*?)(?=\btype=|$)", original["Full_log"])
        sample["command_arguments_excerpt"] = block.group(0).strip() if block else ""
    write_json(output/"review_samples_blind.json", chosen)
    baseline_path = Path("reports/rule_detection/alerts.csv")
    baseline_same = None
    baseline_delta = None
    if baseline_path.exists():
        baseline = pd.read_csv(baseline_path, dtype=str, keep_default_na=False)
        before = set(zip(baseline.source_row_id, baseline.rule_id))
        after = {(a["source_row_id"], a["rule_id"]) for a in atomic}
        baseline_same = before == after
        baseline_delta = {"removed": len(before-after), "added": len(after-before)}
    manifest = {
        "source": str(source), "source_sha256": fingerprint(source), "rules_sha256": fingerprint(DEFAULT_CONFIG),
        "frozen_config_sha256": fingerprint(output/"rules_frozen_v1.0.json"),
        "atomic_sha256": fingerprint(output/"atomic_alerts.json"),
        "samples_sha256": fingerprint(output/"review_samples_blind.json"),
        "python_version": platform.python_version(), "pandas_version": pd.__version__,
        "rows": len(events), "active_rule_ids": active, "disabled_rule_ids": disabled,
        "atomic_alert_count": len(atomic), "merged_alert_count": len(merged),
        "cross_rule_overlapping_events": sum(len(a["rule_ids"]) > 1 for a in merged),
        "exact_duplicate_deliveries": len(atomic)-len({a["alert_id"] for a in atomic}),
        "sample_counts": sample_counts, "production_pairs_same_as_task4": baseline_same,
        "production_pair_delta_from_task4": baseline_delta,
        "sampling": "25 per rule, SHA256(seed|rule_id|source_row_id), seed=20261121; no labels; take all if fewer than 25",
        "run_report": run, "human_signoff": "pending_Tuan_confirmation",
    }
    write_json(output/"preparation_manifest.json", manifest)
    print(json.dumps({k: manifest[k] for k in ("rows", "atomic_alert_count", "merged_alert_count", "cross_rule_overlapping_events", "sample_counts", "production_pairs_same_as_task4")}, indent=2))


def evaluate(source: Path, output: Path) -> None:
    manifest = read_json(output/"preparation_manifest.json")
    for path, expected in ((source, manifest["source_sha256"]), (DEFAULT_CONFIG, manifest["rules_sha256"]),
                           (output/"atomic_alerts.json", manifest["atomic_sha256"]),
                           (output/"review_samples_blind.json", manifest["samples_sha256"]),
                           (output/"rules_frozen_v1.0.json", manifest["frozen_config_sha256"])):
        if fingerprint(path) != expected:
            raise ValueError("Input changed after sampling: "+str(path))
    samples = read_json(output/"review_samples_blind.json")
    notes = read_json(output/"review_notes.json")
    if (output/"evaluation_summary.json").exists():
        previous = read_json(output/"evaluation_summary.json")
        if previous["review_notes_sha256"] != fingerprint(output/"review_notes.json"):
            raise ValueError("Review notes changed after label evaluation; a new evaluation version is required.")
    by_sample = {r["sample_id"]: r for r in notes}
    if len(by_sample) != len(notes) or set(by_sample) != {s["sample_id"] for s in samples}:
        raise ValueError("Review notes must cover each sample exactly once, without duplicates or omissions.")
    for note in notes:
        if type(note.get("suspected_false_positive")) is not bool or not note.get("technical_note") or note.get("reviewer") != "Codex_assisted_raw_review":
            raise ValueError("A sample is missing a valid technical review note.")
    events = normalize_logs(load_logs(source))
    events.attrs = {}
    atomic = read_json(output/"atomic_alerts.json")
    diagnostic = read_json(output/"diagnostic_disabled_alerts.json")
    metrics = evaluate_rule_alerts(events, atomic, manifest["active_rule_ids"])
    metrics["mode"] = "production"
    metrics.to_csv(output/"rule_metrics.csv", index=False, encoding="utf-8-sig")
    baseline_file = Path("reports/rule_detection/alerts.csv")
    baseline_meta = Path("reports/rule_detection/rule_engine_validation.json")
    if baseline_file.exists() and baseline_meta.exists() and read_json(baseline_meta)["source_sha256"] == manifest["source_sha256"]:
        before = pd.read_csv(baseline_file, dtype=str, keep_default_na=False)
        baseline_metrics = evaluate_rule_alerts(events, before.to_dict("records"), manifest["active_rule_ids"])
        baseline_metrics["mode"] = "historical_task4_baseline_not_for_tuning"
        baseline_metrics.to_csv(output/"task4_baseline_metrics.csv", index=False, encoding="utf-8-sig")
    if manifest["disabled_rule_ids"]:
        diag = evaluate_rule_alerts(events, diagnostic, manifest["disabled_rule_ids"])
        diag["mode"] = "diagnostic_disabled_not_production"
        diag.to_csv(output/"diagnostic_rule_metrics.csv", index=False, encoding="utf-8-sig")
    label_values = events.Anomaly.astype("string").str.strip()
    labels = {sid: None if pd.isna(value) else value for sid, value in zip(events.source_row_id, label_values)}
    reviewed = []
    for sample in samples:
        row = {**sample, **by_sample[sample["sample_id"]]}
        label = labels[row["source_row_id"]]
        row["reference_label"] = int(label) if label in {"0", "1"} else None
        row["reference_outcome"] = "TP" if label == "1" else ("FP" if label == "0" else "unscored")
        reviewed.append(row)
    write_json(output/"reviewed_samples.json", reviewed)
    compact = [{k: s[k] for k in ("sample_id", "rule_id", "mode", "source_row_id", "record_index", "reference_label", "reference_outcome", "suspected_false_positive", "technical_review_category", "technical_note", "reviewer", "review_method", "raw_comparison")} for s in reviewed]
    pd.DataFrame(compact).to_csv(output/"sample_review.csv", index=False, encoding="utf-8-sig")
    # Examples selected after scoring are explanatory, not part of the blind sample.
    examples = {}
    for mode, pool in (("production", atomic), ("diagnostic_disabled", diagnostic)):
        for rid in sorted({a["rule_id"] for a in pool}):
            examples[rid] = {"mode": mode}
            for label, name in (("1", "TP"), ("0", "FP")):
                examples[rid][name] = next((a for a in pool if a["rule_id"] == rid and labels[a["source_row_id"]] == label), None)
    write_json(output/"tp_fp_examples.json", examples)
    summary = {
        "rows": len(events), "valid_positive_labels": int(label_values.eq("1").sum()),
        "valid_negative_labels": int(label_values.eq("0").sum()),
        "production_atomic_alerts": len(atomic), "production_merged_events": len(merge_alerts(atomic)),
        "sample_review_count": len(reviewed), "review_counts_by_rule": dict(Counter(s["rule_id"] for s in reviewed)),
        "suspected_fp_counts_by_rule": dict(Counter(s["rule_id"] for s in reviewed if s["suspected_false_positive"])),
        "source_sha256": manifest["source_sha256"], "rules_sha256": manifest["rules_sha256"],
        "review_notes_sha256": fingerprint(output/"review_notes.json"),
        "notes": ["Full-dataset descriptive reference-label evaluation; not a held-out test.",
                  "Recall denominator is all positive-label events, not just each rule's event category.",
                  "Technical suspicion and FP by reference label are separate fields.",
                  "No rule parameter is tuned from these labels; production config stayed frozen after blind preparation.",
                  "Auth has only 8 alerts: all 8 reviewed; no repeated samples fabricated.",
                  "Disabled rule evaluation is diagnostic only and excluded from production union.",
                  "Schema technical freeze v1.0; Tuan signoff pending, no contact or approval fabricated."],
    }
    write_json(output/"evaluation_summary.json", summary)
    print(metrics.to_string(index=False))
    print(json.dumps(summary, ensure_ascii=True, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["prepare", "evaluate"], required=True)
    parser.add_argument("--input", type=Path, default=Path("dataset_log/logs_SPEDIA_annotated_en.csv"))
    parser.add_argument("--output", type=Path, default=Path("reports/rule_validation"))
    args = parser.parse_args()
    if args.input.resolve().parent == args.output.resolve() or args.input.resolve() == args.output.resolve():
        raise ValueError("Output must differ from the source file/directory to avoid overwriting data")
    (prepare if args.phase == "prepare" else evaluate)(args.input, args.output)


if __name__ == "__main__":
    main()
