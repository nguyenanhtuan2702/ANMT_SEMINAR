"""Normalize event records without losing evidence or changing source identity."""
from __future__ import annotations

import copy
import re

import pandas as pd

from preprocessing.contracts import RAW_COLUMNS, REQUIRED_COLUMNS

TEXT_COLUMNS = ("Activity", "Action", "Decoder_name", "User", "Agent_name")
SOURCE_COLUMNS = ("Timestamp", *TEXT_COLUMNS)
SCHEMA_VERSION = "spedia.events.v1"
EVENT_COLUMNS = (
    "source_row_id", "record_index", "id", "Timestamp", "Activity", "Action",
    "Decoder_name", "User", "Agent_name", "hour", "day_of_week", "date",
    "invalid_timestamp", "timestamp_error", *RAW_COLUMNS,
)
OWNED_COLUMNS = {"hour", "day_of_week", "date", "invalid_timestamp", "timestamp_error"} | {
    f"{column}_raw" for column in SOURCE_COLUMNS
}


def normalize_logs(
    logs: pd.DataFrame, *, file_sha256: str | None = None
) -> pd.DataFrame:
    """Return a normalized, chronologically ordered copy of loader output.

    Invalid timestamps are retained as NaT with invalid_timestamp/timestamp_error.
    Source time is naive, with exact YYYY-MM-DD HH:MM:SS.mmm syntax; no timezone
    is invented. hour/day_of_week are nullable integers (Monday=0); date is a
    Python calendar dates (datetime.date, NaT on invalid rows). Invalid times sort last.

    Preserve existing unique nonempty string source_row_id values verbatim. If
    absent, use file_sha256 or attrs['load_report']['file_sha256'] plus original
    record_index; generate indices before sorting only if absent. Never hash
    normalized contents or use Anomaly to decide identity or normalization.

    Existing source fields are copied into *_raw before strip/casefold. The three
    raw log columns and all other source columns remain untouched. Reapplying
    to this function's output is idempotent, including reports and raw backups.
    """
    if not isinstance(logs, pd.DataFrame):
        raise TypeError("normalize_logs requires a pandas DataFrame.")
    if not logs.columns.is_unique:
        raise ValueError("DataFrame contains duplicate column names.")
    missing = sorted(set(REQUIRED_COLUMNS) - set(logs.columns))
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    previous = logs.attrs.get("normalization_report", {})
    repeated = isinstance(previous, dict) and previous.get("schema_version") == SCHEMA_VERSION
    collisions = sorted(OWNED_COLUMNS.intersection(logs.columns))
    if collisions and not repeated:
        raise ValueError("Input contains reserved normalizer columns: " + ", ".join(collisions))
    if repeated and not OWNED_COLUMNS.issubset(logs.columns):
        raise ValueError("Normalized events are missing derived/raw columns; safe renormalization is not possible.")
    frame = logs.copy(deep=True).reset_index(drop=True)
    frame.attrs = copy.deepcopy(logs.attrs)
    if "record_index" not in frame:
        frame["record_index"] = pd.Series(range(len(frame)), dtype="int64")
    else:
        indices = frame["record_index"]
        if (not pd.api.types.is_integer_dtype(indices.dtype)
                or pd.api.types.is_bool_dtype(indices.dtype)
                or indices.isna().any() or indices.lt(0).any() or indices.duplicated().any()):
            raise ValueError("record_index must contain unique, nonmissing, nonnegative integers within the file.")
        frame["record_index"] = indices.astype("int64")
    if "source_row_id" in frame:
        ids = frame["source_row_id"]
        if (ids.isna().any() or not ids.map(lambda value: isinstance(value, str) and bool(value.strip())).astype(bool).all()
                or ids.duplicated().any()):
            raise ValueError("source_row_id must contain unique, nonmissing, nonempty strings; invalid keys are not replaced automatically.")
    else:
        load_report = frame.attrs.get("load_report", {})
        digest = file_sha256 or (load_report.get("file_sha256") if isinstance(load_report, dict) else None)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Missing source_row_id: a valid file_sha256 or SHA-256 from load_report is required.")
        frame["source_row_id"] = frame["record_index"].map(lambda index: f"{digest}:{index:08d}").astype("string")
    frame["source_row_id"] = frame["source_row_id"].astype("string")
    for column in (*RAW_COLUMNS, "Decoder_name"):
        if column not in frame:
            frame[column] = pd.Series(pd.NA, index=frame.index, dtype="string")
    if not repeated:
        for column in SOURCE_COLUMNS:
            frame[f"{column}_raw"] = frame[column].copy(deep=True)
    for column in TEXT_COLUMNS:
        text = frame[f"{column}_raw"].astype("string").str.strip().str.casefold()
        frame[column] = text.mask(text.eq(""), pd.NA)
    # Keep action vocabulary faithful to source: 'URL accedida' becomes
    # 'url accedida'; no translation or attack semantics are inferred.
    timestamp = frame["Timestamp_raw"].astype("string")
    # Use nonnullable masks before combining pandas/Arrow-backed booleans.
    # Missing source timestamps are errors to flag, never an ambiguous pd.NA.
    nonempty = timestamp.notna() & timestamp.str.strip().ne("").fillna(False).astype(bool)
    format_ok = timestamp.str.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}").fillna(False).astype(bool)
    # pandas 3 may initially parse at microsecond resolution. Check the explicit
    # ns target range before astype so out-of-range source rows are flagged,
    # rather than raising during the final dtype conversion (or overflowing).
    within_ns_range = (timestamp.ge("1677-09-21 00:12:43.146") & timestamp.le("2262-04-11 23:47:16.854")).fillna(False).astype(bool)
    parsed = pd.to_datetime(
        timestamp.where(format_ok & within_ns_range, pd.NA), format="%Y-%m-%d %H:%M:%S.%f", errors="coerce"
    ).astype("datetime64[ns]")
    error = pd.Series(pd.NA, index=frame.index, dtype="string")
    error.loc[~nonempty] = "missing_timestamp"
    error.loc[nonempty & ~format_ok] = "invalid_format"
    error.loc[format_ok & parsed.isna()] = "invalid_datetime"
    frame["Timestamp"] = parsed
    frame["invalid_timestamp"] = parsed.isna()
    frame["timestamp_error"] = error
    frame["hour"] = parsed.dt.hour.astype("Int64")
    frame["day_of_week"] = parsed.dt.dayofweek.astype("Int64")
    frame["date"] = parsed.dt.date
    # Input indices may already be sorted/filtered; never replace record_index.
    frame = frame.sort_values(["Timestamp", "record_index"], kind="stable", na_position="last").reset_index(drop=True)
    frame = frame.loc[:, [*EVENT_COLUMNS, *(c for c in frame.columns if c not in EVENT_COLUMNS)]]
    invalid = frame.loc[frame["invalid_timestamp"], ["source_row_id", "record_index", "Timestamp_raw", "timestamp_error"]]
    issues = [
        {"source_row_id": sid, "record_index": int(index),
         "value": None if pd.isna(value) else str(value), "reason": reason}
        for sid, index, value, reason in invalid.itertuples(index=False, name=None)
    ]
    frame.attrs["normalization_report"] = {
        "schema_version": SCHEMA_VERSION, "rows_input": len(logs), "rows_output": len(frame),
        "rows_dropped": 0, "invalid_timestamp_count": len(issues),
        "timestamp_issues": issues, "sort_order": ["Timestamp", "record_index"],
        "invalid_timestamp_position": "last", "timezone": "unspecified (naive)",
        "text_normalization": "strip + casefold; empty -> pd.NA; source retained in *_raw",
        "day_of_week_definition": "Monday=0, Sunday=6",
    }
    return frame


# Public train/inference name: the exact same function object, not a second
# implementation that could drift from offline dataset preparation.
normalize = normalize_logs
