"""Build the shared full normalized CSV and a deterministic dashboard sample.

python -m preprocessing.export_normalized_dataset --input dataset_log/logs_SPEDIA_annotated_en.csv
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform

import pandas as pd

from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize
from preprocessing.normalized_io import read_normalized_logs, save_normalized_logs


def dashboard_sample(events: pd.DataFrame, size: int = 1000, seed: int = 20261122) -> pd.DataFrame:
    if type(size) is not int or size <= 0:
        raise ValueError("Sample size must be a positive integer.")
    count = min(size, len(events))
    mandatory = events.groupby("Activity", sort=False, dropna=False).head(1)
    if len(mandatory) > count:
        raise ValueError("The sample is too small to include at least one event per Activity.")
    rest = events.loc[~events.source_row_id.isin(mandatory.source_row_id)]
    sample = pd.concat([mandatory, rest.sample(n=count-len(mandatory), random_state=seed)])
    sample = sample.sort_values(["Timestamp", "record_index"], kind="stable", na_position="last").reset_index(drop=True)
    sample.attrs = copy.deepcopy(events.attrs)
    sample = normalize(sample)  # Recompute report counts for sample scope, same cleaner.
    sample.attrs["sample_report"] = {"population_rows": len(events), "sample_rows": len(sample), "seed": seed,
                                    "method": "one per Activity + random without replacement; no Anomaly selection",
                                    "intended_use": "dashboard layout, not full-history correlation/metrics"}
    return sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/normalized_logs.csv"))
    parser.add_argument("--sample-output", type=Path, default=Path("data/normalized_logs_sample.csv"))
    parser.add_argument("--sample-size", type=int, default=1000)
    args = parser.parse_args()
    targets = [args.output, args.sample_output, args.output.with_suffix(".schema.json"), args.sample_output.with_suffix(".schema.json")]
    if args.input.resolve() in {p.resolve() for p in targets} or len({p.resolve() for p in targets}) != 4:
        raise ValueError("Outputs must be distinct and must not overwrite the input.")
    digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    events = normalize(load_logs(args.input))
    full_meta = save_normalized_logs(events, args.output)
    restored = read_normalized_logs(args.output)
    pd.testing.assert_frame_equal(events, restored, check_exact=True)
    assert events.attrs == restored.attrs
    pd.testing.assert_frame_equal(normalize(restored), restored, check_exact=True)
    sample = dashboard_sample(events, size=args.sample_size)
    sample_meta = save_normalized_logs(sample, args.sample_output)
    read_sample = read_normalized_logs(args.sample_output)
    pd.testing.assert_frame_equal(sample, read_sample, check_exact=True)
    assert sample.attrs == read_sample.attrs
    assert set(sample.source_row_id).issubset(set(events.source_row_id))
    assert set(sample.Activity.dropna()) == set(events.Activity.dropna())
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == digest
    result = {"python_version": platform.python_version(), "pandas_version": pd.__version__,
              "source_sha256": digest, "full_csv": str(args.output), "rows": len(events), "columns": len(events.columns),
              "full_csv_sha256": full_meta["csv_sha256"], "sample_csv": str(args.sample_output),
              "sample_rows": len(sample), "sample_csv_sha256": sample_meta["csv_sha256"],
              "sample_activity_counts": {str(k): int(v) for k,v in sample.Activity.value_counts().items()},
              "checks": {"full_round_trip_exact": True, "sample_round_trip_exact": True,
                         "metadata_restored": True, "normalize_reloaded_is_idempotent": True,
                         "raw_empty_and_null_values_preserved": True, "sample_uses_original_source_ids": True,
                         "sample_covers_all_activities": True, "input_hash_unchanged": True}}
    folder = Path("reports/log_normalization")
    folder.mkdir(parents=True, exist_ok=True)
    (folder/"export_validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
