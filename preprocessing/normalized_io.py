"""Lossless CSV transport for normalized events plus a checksum/type sidecar.

Use this reader, not load_logs(), for exported normalized CSV: source_row_id
must remain in the ORIGINAL source-file namespace. No optional Parquet engine
or new dependency is needed.
"""
from __future__ import annotations

import copy
from datetime import date, datetime
import hashlib
import json
from pathlib import Path

import pandas as pd

from preprocessing.log_normalizer import EVENT_COLUMNS, OWNED_COLUMNS, SCHEMA_VERSION

FORMAT_VERSION = "spedia.normalized_csv.v1"


def _manifest_path(path: Path) -> Path:
    return path.with_suffix(".schema.json")


def _validate(frame: pd.DataFrame) -> None:
    if not isinstance(frame, pd.DataFrame) or not frame.columns.is_unique:
        raise ValueError("A normalized DataFrame with unique column names is required.")
    missing = (set(EVENT_COLUMNS) | OWNED_COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError("Missing normalized event columns: " + ", ".join(sorted(missing)))
    report = frame.attrs.get("normalization_report", {})
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Missing normalization metadata; use normalize(load_logs(...)) before saving.")
    if not pd.api.types.is_datetime64_any_dtype(frame.Timestamp) or frame.Timestamp.dt.tz is not None:
        raise ValueError("Normalized Timestamp must be timezone-naive datetime.")
    if (frame.source_row_id.isna().any() or frame.source_row_id.duplicated().any()
            or not frame.source_row_id.map(lambda value: isinstance(value, str) and bool(value.strip())).astype(bool).all()):
        raise ValueError("source_row_id must be unique and nonmissing.")
    if (not pd.api.types.is_integer_dtype(frame.record_index.dtype)
            or pd.api.types.is_bool_dtype(frame.record_index.dtype) or frame.record_index.isna().any()
            or frame.record_index.lt(0).any() or frame.record_index.duplicated().any()):
        raise ValueError("record_index must be unique and nonmissing.")


def _column_spec(frame: pd.DataFrame, column: str) -> dict:
    values, dtype = frame[column], frame[column].dtype
    if isinstance(dtype, pd.StringDtype):
        kind = "string"
    elif pd.api.types.is_datetime64_any_dtype(dtype):
        if values.dt.tz is not None:
            raise ValueError(f"Timezones are not supported in column {column}.")
        kind = "datetime"
    elif pd.api.types.is_bool_dtype(dtype):
        kind = "boolean"
    elif pd.api.types.is_integer_dtype(dtype) or pd.api.types.is_float_dtype(dtype):
        kind = "numeric"
    elif column == "date" and values.dropna().map(lambda x: isinstance(x, date) and not isinstance(x, datetime)).all():
        kind = "date"
    elif dtype == object and values.dropna().map(lambda x: isinstance(x, str)).all():
        kind = "object_string"
    else:
        raise ValueError(f"Unsupported dtype for lossless storage: {column} ({dtype}).")
    return {"name": column, "kind": kind, "pandas_dtype": str(dtype)}


def save_normalized_logs(logs: pd.DataFrame, path: str | Path) -> dict:
    """Save CSV and .schema.json, preserving null vs empty/NA-like strings.

    The marker is chosen not to equal any actual string cell. CSV has no native
    dtypes/attrs: the paired sidecar carries those plus a SHA-256 checksum.
    Do not transfer the CSV without its sidecar.
    """
    _validate(logs)
    path = Path(path)
    if path.suffix.casefold() != ".csv":
        raise ValueError("This exporter supports .csv; a Parquet engine is not configured.")
    source_sha = logs.attrs.get("load_report", {}).get("file_sha256")
    if path.exists() and source_sha and hashlib.sha256(path.read_bytes()).hexdigest() == source_sha:
        raise ValueError("Refusing to overwrite the original source file.")
    specs = [_column_spec(logs, column) for column in logs.columns]
    # Validate metadata serializability before writing any file.
    attrs = json.loads(json.dumps(copy.deepcopy(logs.attrs), ensure_ascii=False, allow_nan=False))
    marker, suffix = "__SPEDIA_NULL__", 0
    text_columns = [s["name"] for s in specs if s["kind"] in {"string", "object_string"}]
    while any(logs[c].eq(marker).fillna(False).any() for c in text_columns):
        suffix += 1
        marker = f"__SPEDIA_NULL__{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    logs.to_csv(path, index=False, encoding="utf-8-sig", na_rep=marker,
                date_format="%Y-%m-%d %H:%M:%S.%f", lineterminator="\n")
    metadata = {"format_version": FORMAT_VERSION, "event_schema_version": SCHEMA_VERSION,
                "encoding": "utf-8-sig", "row_count": len(logs), "column_count": len(specs),
                "columns": specs, "null_marker": marker,
                "csv_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "attrs": attrs}
    _manifest_path(path).write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return metadata


def read_normalized_logs(path: str | Path) -> pd.DataFrame:
    """Restore logical dtypes, original keys and attrs; reject missing/stale sidecar."""
    path = Path(path)
    sidecar = _manifest_path(path)
    if not sidecar.is_file():
        raise FileNotFoundError(f"Missing metadata {sidecar}; transfer the CSV together with its .schema.json.")
    metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    if metadata.get("format_version") != FORMAT_VERSION or metadata.get("event_schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported normalized CSV/schema version.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["csv_sha256"]:
        raise ValueError("Checksum of CSV does not match metadata; the file may have been modified or incompletely copied.")
    frame = pd.read_csv(path, encoding=metadata["encoding"], dtype="string", keep_default_na=False,
                        na_values=[metadata["null_marker"]], skip_blank_lines=False)
    specs = metadata["columns"]
    if (frame.columns.tolist() != [s["name"] for s in specs] or len(frame) != metadata["row_count"]
            or len(frame.columns) != metadata["column_count"]):
        raise ValueError("CSV row/column counts do not match metadata.")
    for spec in specs:
        name, kind, dtype = spec["name"], spec["kind"], spec["pandas_dtype"]
        values = frame[name]
        if kind == "datetime":
            frame[name] = pd.to_datetime(values, format="%Y-%m-%d %H:%M:%S.%f", errors="raise").astype(dtype)
        elif kind == "date":
            frame[name] = pd.to_datetime(values, format="%Y-%m-%d", errors="raise").dt.date
        elif kind == "numeric":
            frame[name] = pd.to_numeric(values, errors="raise").astype(dtype)
        elif kind == "boolean":
            if not values.dropna().isin(["True", "False"]).all():
                raise ValueError(f"Invalid boolean value in {name}.")
            frame[name] = values.map({"True": True, "False": False}).astype(dtype)
        elif kind == "string":
            frame[name] = values.astype("string")
        elif kind == "object_string":
            frame[name] = values.astype(object)
        else:
            raise ValueError(f"Unsupported kind: {name}/{kind}.")
    frame.attrs = copy.deepcopy(metadata["attrs"])
    _validate(frame)
    return frame
