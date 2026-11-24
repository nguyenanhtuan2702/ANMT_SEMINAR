"""Explicit full-dataset audit (not part of the small fixture test suite).

python tests/validate_log_loader_dataset.py --input dataset_log/logs_SPEDIA_annotated_en.csv --expected-rows 72250
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import platform
import sys
from pathlib import Path

import pandas as pd

# Support invocation as a script from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.log_loader import NUMERIC_COLUMNS, load_logs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-rows", type=int)
    parser.add_argument("--output", type=Path, default=Path("reports/log_loading/load_validation.json"))
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        raise ValueError("Output must not overwrite the source dataset")
    data = args.input.read_bytes()
    frame = load_logs(args.input)
    report = frame.attrs["load_report"]
    assert report["rows_read"] == report["rows_loaded"] == len(frame)
    assert report["rows_skipped"] == 0 and report["missing_columns"] == []
    if args.expected_rows is not None:
        assert len(frame) == args.expected_rows
    assert frame.source_row_id.nunique() == len(frame)
    # Fetch columns once: repeatedly fetching cells can repeatedly copy attrs in
    # some pandas versions. Arrays still compare every single source field.
    with args.input.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        source_columns = reader.fieldnames or []
        raw_columns = [c for c in ("Full_log", "Description", "Content") if c in source_columns]
        numeric_columns = [c for c in NUMERIC_COLUMNS if c in source_columns]
        raw = {c: frame[c].tolist() for c in raw_columns}
        numbers = {c: frame[c+"_raw"].tolist() for c in numeric_columns}
        ids = frame.source_row_id.tolist()
        indexes = frame.record_index.tolist()
        count = 0
        for index, row in enumerate(reader):
            for column in raw_columns:
                assert raw[column][index] == row[column], (index, column)
            for column in numeric_columns:
                assert numbers[column][index] == row[column], (index, column)
            assert indexes[index] == index
            assert ids[index] == report["file_sha256"]+f":{index:08d}"
            count += 1
    assert count == len(frame)
    upload = io.BytesIO(data)
    upload.seek(min(100, len(data)))
    position = upload.tell()
    uploaded = load_logs(upload)
    assert upload.tell() == position and not upload.closed
    pd.testing.assert_frame_equal(frame, uploaded)
    assert frame.attrs["load_report"] == uploaded.attrs["load_report"]
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == report["file_sha256"]
    result = {
        "source": args.input.as_posix(), "python_version": platform.python_version(),
        "pandas_version": pd.__version__, "output_shape": list(frame.shape),
        "missing_users": int(frame.User.isna().sum()),
        "rows_with_numeric_issues": int(frame.has_numeric_issue.sum()),
        "load_report": report,
        "checks": {"all_raw_values_preserved": True, "all_numeric_source_values_preserved": True,
                   "path_and_upload_frames_equal": True, "upload_cursor_preserved": True,
                   "source_hash_unchanged": True, "unique_source_row_ids": True,
                   "source_row_ids_match_record_positions": True},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "rows_read": report["rows_read"],
                      "rows_loaded": report["rows_loaded"], "rows_skipped": report["rows_skipped"],
                      "missing_columns": report["missing_columns"],
                      "numeric_issues": len(report["numeric_issues"]), "checks": result["checks"]}, indent=2))


if __name__ == "__main__":
    main()
