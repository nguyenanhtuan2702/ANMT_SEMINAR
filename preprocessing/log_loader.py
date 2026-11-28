"""Read SPEDIA CSV paths or binary uploads without silently losing raw evidence."""
from __future__ import annotations

import csv
import hashlib
import io
import math
import os
from pathlib import Path
from typing import BinaryIO, Literal

import pandas as pd

from preprocessing.contracts import RAW_COLUMNS, REQUIRED_COLUMNS

NUMERIC_COLUMNS = ("Attachments", "Size", "Size_before", "Size_after", "Level")
RESERVED_COLUMNS = {"source_row_id", "record_index", "has_numeric_issue"} | {
    f"{column}_raw" for column in NUMERIC_COLUMNS
}


class LogLoadError(ValueError):
    """Invalid CSV/schema; report remains available even when no frame is returned."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


class LogEncodingError(UnicodeError):
    """Encoding failure with the same reporting interface as LogLoadError."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


def _read_bytes(source: str | os.PathLike | BinaryIO) -> bytes:
    if isinstance(source, (str, os.PathLike)):
        return Path(source).read_bytes()
    # Streamlit UploadedFile inherits BytesIO. getvalue() reads the entire upload
    # regardless of its cursor position and does not close or advance the stream.
    if callable(getattr(source, "getvalue", None)):
        data = source.getvalue()
    elif all(callable(getattr(source, attr, None)) for attr in ("read", "seek", "tell")):
        position = source.tell()
        try:
            source.seek(0)
            data = source.read()
        finally:
            source.seek(position)
    else:
        raise TypeError("Source must be a path or a seekable binary upload.")
    if not isinstance(data, bytes):
        raise TypeError("Uploads must return bytes; text streams cannot preserve the original byte hash.")
    return data


def load_logs(
    csv_path: str | os.PathLike | BinaryIO,
    *,
    encoding: str = "utf-8-sig",
    on_bad_lines: Literal["error", "skip"] = "error",
) -> pd.DataFrame:
    """Load a path or binary upload, returning a DataFrame plus attrs['load_report'].

    Optional numeric fields become nullable Float64, with their exact source text
    in <column>_raw. Invalid/nonfinite numbers are flagged and become pd.NA;
    negative values are retained and flagged. Raw log fields are never changed.
    Timestamp stays text for the normalizer; Anomaly stays an optional string
    reference label. No sorting or duplicate-ID removal occurs here.

    error: reject damaged/required-empty records (default). skip: skip only records
    with recoverable field-count or required-value errors. Broken CSV quoting is
    always fatal because the next record boundary cannot be trusted.

    Raises FileNotFoundError, LogEncodingError, LogLoadError, or TypeError.
    Input uploads are not closed and their cursor position is preserved.
    """
    if on_bad_lines not in {"error", "skip"}:
        raise ValueError("on_bad_lines must be 'error' or 'skip'.")
    data = _read_bytes(csv_path)
    digest = hashlib.sha256(data).hexdigest()
    report = {
        "status": "loading", "encoding": encoding, "file_sha256": digest,
        "on_bad_lines": on_bad_lines, "rows_read": 0, "rows_loaded": 0,
        "rows_skipped": 0, "missing_columns": [], "blank_lines_ignored": 0,
        "skipped_records": [], "numeric_issues": [], "duplicate_id_rows": 0,
    }

    def fail(message: str) -> None:
        report["status"] = "error"
        raise LogLoadError(message, report)

    try:
        text = data.decode(encoding)
    except UnicodeError as error:
        report["status"] = "error"
        raise LogEncodingError(
            f"Cannot decode CSV using {encoding}. Provide the correct encoding; encoding is not guessed.", report
        ) from error
    if not text.strip("\ufeff \t\r\n"):
        fail("The CSV is empty or contains only whitespace/BOM.")
    if "\x00" in text:
        fail("CSV contains NUL characters; check the encoding or whether the file is binary.")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        columns = next(reader)
    except (StopIteration, csv.Error) as error:
        fail(f"Cannot read the CSV header: {error}")
    report["missing_columns"] = sorted(set(REQUIRED_COLUMNS) - set(columns))
    if report["missing_columns"]:
        fail("Missing required columns: " + ", ".join(report["missing_columns"]))
    if any(not column.strip() for column in columns):
        fail("The CSV header contains an empty column name.")
    if len(columns) != len(set(columns)):
        fail("The CSV header contains duplicate column names.")
    reserved = sorted(RESERVED_COLUMNS.intersection(columns))
    if reserved:
        fail("CSV contains reserved loader metadata columns: " + ", ".join(reserved))

    accepted = []
    record_index = 0
    while True:
        start_line = reader.line_num + 1
        try:
            values = next(reader)
        except StopIteration:
            break
        except csv.Error as error:
            report["unrecoverable_record"] = {
                "record_index": record_index, "physical_line_start": start_line,
                "physical_line_end": reader.line_num,
            }
            fail(f"Malformed CSV at record {record_index}, physical line {start_line}: {error}. Record boundaries cannot be determined for safe skipping.")
        if not values:
            report["blank_lines_ignored"] += 1
            continue
        index = record_index
        record_index += 1
        report["rows_read"] += 1
        reason = None
        row = dict(zip(columns, values))
        if len(values) != len(columns):
            reason = f"Incorrect field count: expected {len(columns)}, got {len(values)}"
        else:
            empty = [c for c in REQUIRED_COLUMNS if c != "User" and not row[c].strip()]
            if empty:
                reason = "Empty required values: " + ", ".join(empty)
        if reason:
            issue = {"record_index": index, "source_row_id": f"{digest}:{index:08d}",
                     "physical_line_start": start_line, "physical_line_end": reader.line_num,
                     "reason": reason}
            if on_bad_lines == "error":
                report["invalid_record"] = issue
                fail(f"Record {index}, physical line {start_line}: {reason}.")
            report["rows_skipped"] += 1
            report["skipped_records"].append(issue)
            continue
        row["record_index"] = index
        row["source_row_id"] = f"{digest}:{index:08d}"
        accepted.append(row)
    if not accepted:
        fail("CSV has no valid records (header only or all records skipped).")

    frame = pd.DataFrame(accepted)
    for column in columns:
        frame[column] = frame[column].astype("string")
    frame["source_row_id"] = frame["source_row_id"].astype("string")
    frame["record_index"] = frame["record_index"].astype("int64")
    # Raw empty strings stay empty strings. Missing optional raw columns are
    # represented as nullable strings without inventing evidence.
    for column in RAW_COLUMNS:
        if column not in frame:
            frame[column] = pd.Series(pd.NA, index=frame.index, dtype="string")
    frame["User"] = frame["User"].mask(frame["User"].str.strip().eq(""), pd.NA)
    frame["has_numeric_issue"] = False
    for column in NUMERIC_COLUMNS:
        if column not in frame:
            continue
        original = frame[column].copy()
        frame[f"{column}_raw"] = original
        # to_numeric may infer nonnullable integer dtypes; explicit Float64 gives
        # a consistent nullable representation across pandas 2.x and 3.x.
        numeric = pd.to_numeric(original.mask(original.str.strip().eq(""), pd.NA), errors="coerce").astype("Float64")
        finite = numeric.map(lambda value: pd.isna(value) or math.isfinite(value))
        invalid = original.str.strip().ne("") & (numeric.isna() | ~finite)
        numeric = numeric.mask(~finite, pd.NA)
        negative = numeric.lt(0).fillna(False)
        for position in frame.index[invalid | negative]:
            report["numeric_issues"].append({
                "source_row_id": frame.at[position, "source_row_id"],
                "record_index": int(frame.at[position, "record_index"]), "column": column,
                "value": original.at[position],
                "reason": "invalid_or_nonfinite_numeric" if invalid.at[position] else "negative_numeric",
            })
        frame.loc[invalid | negative, "has_numeric_issue"] = True
        frame[column] = numeric
    report["duplicate_id_rows"] = int(frame["id"].duplicated().sum())
    report["rows_loaded"] = len(frame)
    report["status"] = "success"
    frame.attrs["load_report"] = report
    return frame
