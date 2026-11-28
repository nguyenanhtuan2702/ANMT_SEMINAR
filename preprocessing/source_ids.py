from __future__ import annotations

import pandas as pd


def validate_source_row_ids(
    frame: pd.DataFrame,
    *,
    component: str,
    unique: bool = True,
) -> pd.Series:
    if "source_row_id" not in frame.columns:
        raise ValueError(f"{component} thiếu cột source_row_id.")

    source_ids = frame["source_row_id"].astype("string")
    blank_ids = source_ids.isna() | source_ids.str.strip().eq("").fillna(True)
    if blank_ids.any():
        raise ValueError(f"{component} yêu cầu source_row_id không rỗng.")
    if unique and source_ids.duplicated().any():
        raise ValueError(f"{component} yêu cầu source_row_id duy nhất.")
    return source_ids
