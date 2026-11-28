"""Typed detected CSV: normalized transport plus JSON current-event rule_ids."""
import json
from pathlib import Path

import pandas as pd

from detection.pipeline import DETECTION_COLUMNS
from preprocessing.normalized_io import save_normalized_logs, read_normalized_logs


def _validate(logs):
    missing = sorted(set(DETECTION_COLUMNS)-set(logs.columns))
    if missing:
        raise ValueError("Missing detection columns: " + ", ".join(missing))
    if logs.attrs.get("detection_schema_version") != "spedia.detected.v1":
        raise ValueError("Missing detected v1 metadata; run run_detection_pipeline first.")
    if not logs.rule_ids.map(lambda x: isinstance(x, list) and all(isinstance(r, str) and r for r in x) and x == sorted(set(x))).astype(bool).all():
        raise ValueError("rule_ids must be a sorted list of unique rule IDs.")
    if (str(logs.alert_count.dtype) != "Int64" or logs.alert_count.isna().any()
            or not logs.rule_ids.str.len().eq(logs.alert_count).all()):
        raise ValueError("alert_count must be Int64 and equal the current event's rule_ids count.")
    if (not logs.severity.dropna().isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).all()
            or not logs.severity.notna().eq(logs.alert_count.gt(0)).all()):
        raise ValueError("Severity must be set only for events with alerts.")


def save_detected_logs(logs: pd.DataFrame, path="data/detected_logs.csv") -> dict:
    _validate(logs)
    path = Path(path)
    if path.exists():
        sidecar = path.with_suffix(".schema.json")
        if not sidecar.exists() or json.loads(sidecar.read_text(encoding="utf-8")).get("attrs", {}).get("detection_schema_version") != "spedia.detected.v1":
            raise ValueError("Refusing to overwrite a file not identified as detected logs.")
    wire = logs.copy(deep=True)
    wire["rule_ids"] = wire.rule_ids.map(lambda x: json.dumps(x, ensure_ascii=False)).astype("string")
    return save_normalized_logs(wire, path)


def read_detected_logs(path="data/detected_logs.csv") -> pd.DataFrame:
    logs = read_normalized_logs(path)
    if "rule_ids" not in logs:
        raise ValueError("The file has no detected-log rule_ids column.")
    logs["rule_ids"] = logs.rule_ids.map(json.loads).astype(object)
    _validate(logs)
    return logs
