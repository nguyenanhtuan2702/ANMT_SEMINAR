"""CSV ingestion and schema validation for event logs."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import BinaryIO

import pandas as pd

from preprocessing.source_ids import validate_source_row_ids


REQUIRED_COLUMNS = {
    "Timestamp",
    "User",
    "Agent_name",
    "Activity",
    "Action",
    "Decoder_name",
}


def load_log_csv(source: str | Path | bytes | bytearray | BinaryIO) -> pd.DataFrame:
    """Read an uploaded/path CSV and attach stable IDs derived from its bytes."""
    if isinstance(source, (str, Path)):
        raw_bytes = Path(source).read_bytes()
    elif isinstance(source, (bytes, bytearray)):
        raw_bytes = bytes(source)
    elif hasattr(source, "getvalue"):
        raw_bytes = source.getvalue()
    else:
        position = source.tell() if source.seekable() else None
        raw_bytes = source.read()
        if position is not None:
            source.seek(position)

    try:
        frame = pd.read_csv(io.BytesIO(raw_bytes))
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError, ValueError) as error:
        raise ValueError(f"CSV không đọc được: {error}") from error

    if frame.empty:
        raise ValueError("CSV không có bản ghi.")
    duplicated_columns = frame.columns[frame.columns.duplicated()].tolist()
    if duplicated_columns:
        raise ValueError(
            "CSV có tên cột trùng lặp: " + ", ".join(map(str, duplicated_columns))
        )
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise ValueError("Thiếu cột bắt buộc: " + ", ".join(sorted(missing)))

    source_hash = hashlib.sha256(raw_bytes).hexdigest()
    if "source_row_id" not in frame.columns:
        frame.insert(0, "source_row_id", [
            f"{source_hash}:{index:08d}" for index in range(len(frame))
        ])
    else:
        frame["source_row_id"] = frame["source_row_id"].astype("string")
    if "record_index" not in frame.columns:
        frame.insert(1, "record_index", range(len(frame)))
    else:
        try:
            indices = pd.to_numeric(frame["record_index"], errors="raise")
            if indices.isna().any() or indices.mod(1).ne(0).any():
                raise ValueError("record_index phải là số nguyên hợp lệ.")
            frame["record_index"] = indices.astype("int64")
        except (TypeError, ValueError) as error:
            raise ValueError("record_index phải là số nguyên hợp lệ.") from error
    frame["source_row_id"] = validate_source_row_ids(
        frame,
        component="Loader",
    )
    return frame
