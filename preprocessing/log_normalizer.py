"""Normalize event fields while preserving source values for investigation."""
from __future__ import annotations

import pandas as pd

from preprocessing.source_ids import validate_source_row_ids


CATEGORICAL_COLUMNS = (
    "Activity",
    "Action",
    "Decoder_name",
    "User",
    "Agent_name",
)


def normalize_logs(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a normalized copy while preserving Loader-assigned row IDs."""
    required = {
        "Timestamp",
        "User",
        "Agent_name",
        "Activity",
        "Action",
        "Decoder_name",
    }
    missing = required - set(frame.columns)
    if missing:
        raise ValueError("Thiếu cột bắt buộc: " + ", ".join(sorted(missing)))
    if frame.empty:
        raise ValueError("Không thể chuẩn hóa CSV không có bản ghi.")

    source_row_ids = validate_source_row_ids(
        frame,
        component="Normalizer",
    )
    result = frame.copy()
    result["source_row_id"] = source_row_ids
    if "record_index" not in result.columns:
        result.insert(1 if "source_row_id" in result.columns else 0,
                      "record_index", range(len(result)))
    else:
        try:
            indices = pd.to_numeric(result["record_index"], errors="raise")
            if indices.isna().any() or indices.mod(1).ne(0).any():
                raise ValueError("record_index phải là số nguyên hợp lệ.")
            result["record_index"] = indices.astype("int64")
        except (TypeError, ValueError) as error:
            raise ValueError("record_index phải là số nguyên hợp lệ.") from error
    if "Timestamp_raw" not in result.columns:
        result["Timestamp_raw"] = result["Timestamp"].astype("string")
    parsed_timestamp = pd.to_datetime(
        result["Timestamp"], errors="coerce"
    ).astype("datetime64[ns]")
    result["Timestamp"] = parsed_timestamp
    result["invalid_timestamp"] = parsed_timestamp.isna()
    if "timestamp_error" not in result.columns:
        result["timestamp_error"] = pd.Series(pd.NA, index=result.index, dtype="string")
    result.loc[result["invalid_timestamp"], "timestamp_error"] = (
        "Timestamp không parse được"
    )

    for column in CATEGORICAL_COLUMNS:
        raw_column = f"{column}_raw"
        if raw_column not in result.columns:
            result[raw_column] = result[column].astype("string")
        values = result[column].astype("string").str.strip().str.casefold()
        result[column] = values.replace("", pd.NA)

    valid_time = result["Timestamp"].notna()
    result["hour"] = result["Timestamp"].dt.hour.astype("Int64")
    result["day_of_week"] = result["Timestamp"].dt.dayofweek.astype("Int64")
    result["date"] = result["Timestamp"].dt.date
    result["invalid_timestamp"] = ~valid_time
    return result
