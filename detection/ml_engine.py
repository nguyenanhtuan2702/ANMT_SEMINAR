"""Machine-learning inference engine for dashboard integration."""
from pathlib import Path
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT_DIR / "models" / "artifacts"
BEHAVIORAL_FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "Activity",
    "Action",
    "Decoder_name",
    "User_events_15min_past",
    "Agent_name_events_15min_past",
]
FULL_FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "Activity",
    "Action",
    "Decoder_name",
    "User",
    "Agent_name",
    "User_events_15min_past",
    "Agent_name_events_15min_past",
]


def add_past_window_features(df: pd.DataFrame, window: str = "15min") -> pd.DataFrame:
    result = df.copy()
    result["Timestamp"] = pd.to_datetime(result["Timestamp"], errors="coerce")
    result = result.sort_values("Timestamp", kind="stable").reset_index(drop=True)

    for column in ["User", "Agent_name"]:
        name = f"{column}_events_{window}_past"
        result[name] = 0.0
        for _, group in result.groupby(column, dropna=False):
            group = group.sort_values("Timestamp", kind="stable")
            timestamps = group["Timestamp"].to_numpy(dtype="datetime64[ns]")
            lower_bounds = timestamps - pd.Timedelta(window).to_timedelta64()
            first_in_window = np.searchsorted(timestamps, lower_bounds, side="right")
            before_current = np.searchsorted(timestamps, timestamps, side="left")
            values = before_current - first_in_window
            result.loc[group.index, name] = values
    return result


def prepare_ml_input(df: pd.DataFrame) -> pd.DataFrame:
    required = {
        "Timestamp",
        "User",
        "Agent_name",
        "Activity",
        "Action",
        "Decoder_name",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError("Thiếu cột bắt buộc: " + ", ".join(sorted(missing)))

    result = df.copy()
    result["Timestamp"] = pd.to_datetime(result["Timestamp"], errors="coerce")
    if result["Timestamp"].isna().any():
        raise ValueError("Có Timestamp không hợp lệ.")

    result["hour"] = result["Timestamp"].dt.hour
    result["day_of_week"] = result["Timestamp"].dt.day_name()
    for column in ["Activity", "Action", "Decoder_name", "User", "Agent_name"]:
        result[column] = result[column].fillna("Unknown").astype(str)
    return add_past_window_features(result)


def make_source_row_ids(df: pd.DataFrame) -> pd.Series:
    if "id" in df.columns:
        ids = df["id"].where(df["id"].notna(), "").astype(str)
        if ids.nunique(dropna=False) == len(df) and ids.ne("").all():
            return ids
    return pd.Series([f"row_{index + 1}" for index in range(len(df))], index=df.index)


@lru_cache(maxsize=3)
def _load_pipeline(path: str, modified_ns: int, size: int):
    """Reuse inference artifacts; file version keys invalidate replaced models.

    Cached pipelines are used only for predict, never fit or altered in place.
    """
    return joblib.load(path)


def predict(
    df: pd.DataFrame,
    model_name: str = "random_forest_behavioral.joblib",
    threshold: float = 0.52,
) -> pd.DataFrame:
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("Threshold phải nằm trong khoảng [0, 1].")

    model_path = MODEL_DIR / model_name
    if not model_path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy model ML: {model_path}. "
            "Vui lòng chạy train_model.py và đặt artifact vào models/artifacts."
        )

    inference_df = df.copy()
    inference_df["_source_row_id"] = make_source_row_ids(df)
    prepared = prepare_ml_input(inference_df)
    source_ids = prepared["_source_row_id"].astype(str)
    version = model_path.stat()
    pipeline = _load_pipeline(str(model_path.resolve()), version.st_mtime_ns, version.st_size)
    feature_columns = (
        FULL_FEATURE_COLUMNS
        if model_name in {"random_forest.joblib", "logistic_regression.joblib"}
        else BEHAVIORAL_FEATURE_COLUMNS
    )
    probabilities = pipeline.predict_proba(prepared[feature_columns])[:, 1]
    predicted = (probabilities >= threshold).astype(int)

    return pd.DataFrame(
        {
            "source_row_id": source_ids,
            "timestamp": prepared["Timestamp"],
            "user": prepared["User"],
            "agent": prepared["Agent_name"],
            "activity": prepared["Activity"],
            "action": prepared["Action"],
            "predicted_label": predicted,
            "anomaly_score": probabilities,
        },
        index=prepared.index,
    )
