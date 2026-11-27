"""Confirm the persisted shared input is equivalent for rules and correlation."""
import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection.alert_aggregation import merge_alerts
from detection.correlation import correlate
from detection.rule_engine import DEFAULT_CONFIG, detect_rules
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize
from preprocessing.normalized_io import read_normalized_logs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dataset_log/logs_SPEDIA_annotated_en.csv"))
    parser.add_argument("--normalized", type=Path, default=Path("data/normalized_logs.csv"))
    parser.add_argument("--sample", type=Path, default=Path("data/normalized_logs_sample.csv"))
    args = parser.parse_args()
    source_hash = hashlib.sha256(args.input.read_bytes()).hexdigest()
    rule_hash = hashlib.sha256(DEFAULT_CONFIG.read_bytes()).hexdigest()
    expected = normalize(load_logs(args.input))
    actual = read_normalized_logs(args.normalized)
    sample = read_normalized_logs(args.sample)
    pd.testing.assert_frame_equal(expected, actual, check_exact=True)
    assert expected.attrs == actual.attrs
    before_alerts = detect_rules(expected.drop(columns="Anomaly", errors="ignore"))
    after_alerts = detect_rules(actual.drop(columns="Anomaly", errors="ignore"))
    assert before_alerts == after_alerts
    before_groups = correlate(expected, merge_alerts(before_alerts))
    after_groups = correlate(actual, merge_alerts(after_alerts))
    pd.testing.assert_frame_equal(before_groups, after_groups, check_exact=True)
    assert len(actual) == 72250 and len(sample) == 1000
    assert sample.source_row_id.nunique() == 1000
    assert set(sample.source_row_id).issubset(set(actual.source_row_id))
    assert hashlib.sha256(DEFAULT_CONFIG.read_bytes()).hexdigest() == rule_hash
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == source_hash
    result = {"rows": len(actual), "columns": len(actual.columns), "sample_rows": len(sample),
              "source_sha256": source_hash, "rules_sha256": rule_hash,
              "rule_alert_count": len(after_alerts), "correlation_group_count": len(after_groups),
              "checks": {"in_memory_and_restored_exact": True, "same_rule_alerts": True,
                         "same_correlation_groups": True, "sample_ids_are_original": True,
                         "source_and_frozen_rules_unchanged": True}}
    path = Path("reports/log_normalization/shared_input_validation.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
