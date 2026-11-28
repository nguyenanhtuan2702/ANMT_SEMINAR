"""UI-independent upload and ML integration helpers."""
import copy
import json
import math
import time
from pathlib import Path

import pandas as pd

from detection.pipeline import run_detection_pipeline
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize
from preprocessing.source_ids import validate_source_row_ids


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT_DIR / "models" / "artifacts"
THRESHOLD_CONFIG = PROJECT_DIR / "reports" / "ml" / "model_thresholds.json"
DEFAULT_MODEL = "random_forest_behavioral.joblib"
DEFAULT_THRESHOLD = 0.52
MODEL_NAMES = (
    "logistic_regression.joblib",
    "random_forest.joblib",
    DEFAULT_MODEL,
)
MODEL_LABELS = {
    "logistic_regression.joblib": "Logistic Regression",
    "random_forest.joblib": "Random Forest",
    DEFAULT_MODEL: "Random Forest Behavioral",
}


def run_upload_pipeline(source):
    started = time.perf_counter()
    loaded = load_logs(source)
    load_seconds = time.perf_counter()-started
    step = time.perf_counter()
    normalized = normalize(loaded)
    normalize_seconds = time.perf_counter()-step
    result = run_detection_pipeline(normalized)
    result["report"]["timings_seconds"].update(load=load_seconds, normalize=normalize_seconds,
                                             upload_total=time.perf_counter()-started)
    result["report"]["load"] = copy.deepcopy(loaded.attrs["load_report"])
    result["detected_logs"].attrs["pipeline_report"] = copy.deepcopy(result["report"])
    # Keep the full normalized input available for ML, which needs the complete
    # event history before any Dashboard display filters are applied.
    result["normalized_logs"] = normalized.copy(deep=True)
    return result


def resolve_model_threshold(model_name, config_path=THRESHOLD_CONFIG):
    """Return a model's configured threshold and an optional fallback notice."""
    if model_name not in MODEL_NAMES:
        raise ValueError(f"Model ML không được hỗ trợ: {model_name}")

    try:
        with Path(config_path).open("r", encoding="utf-8") as handle:
            configured = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return DEFAULT_THRESHOLD, (
            f"Không đọc được cấu hình threshold ({error}); đang dùng fallback "
            f"{DEFAULT_THRESHOLD:.2f}."
        )

    if not isinstance(configured, dict):
        return DEFAULT_THRESHOLD, (
            f"Cấu hình threshold không phải object; đang dùng fallback {DEFAULT_THRESHOLD:.2f}."
        )

    value = configured.get(model_name)
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0.0 <= value <= 1.0):
        return DEFAULT_THRESHOLD, (
            f"Threshold cho {model_name} thiếu hoặc không hợp lệ; "
            f"đang dùng fallback {DEFAULT_THRESHOLD:.2f}."
        )
    return float(value), None


def model_artifact_version(model_name):
    """Return a cache version that changes when the selected artifact changes."""
    if model_name not in MODEL_NAMES:
        raise ValueError(f"Model ML không được hỗ trợ: {model_name}")
    path = MODEL_DIR / model_name
    try:
        stat = path.stat()
    except OSError:
        return "missing"
    return f"{stat.st_mtime_ns}:{stat.st_size}"


def run_ml_inference(normalized_events, model_name, threshold):
    """Run ML on the full normalized frame and validate its event-key output."""
    source_ids = validate_source_row_ids(normalized_events, component="Input ML")
    if model_name not in MODEL_NAMES:
        raise ValueError(f"Model ML không được hỗ trợ: {model_name}")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("Threshold phải là số trong khoảng [0, 1].")
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("Threshold phải nằm trong khoảng [0, 1].")

    # Import lazily so an unavailable ML dependency/artifact cannot prevent the
    # Rule dashboard from loading or processing an upload.
    from detection.ml_engine import predict

    inference_input = normalized_events.drop(columns=["Anomaly", "Level"], errors="ignore").copy()
    output = predict(inference_input, model_name=model_name, threshold=float(threshold))
    if not isinstance(output, pd.DataFrame):
        raise ValueError("ML predict() phải trả về DataFrame.")
    required = {"source_row_id", "predicted_label", "anomaly_score"}
    missing = sorted(required - set(output.columns))
    if missing:
        raise ValueError("ML thiếu cột đầu ra: " + ", ".join(missing))

    output_ids = validate_source_row_ids(output, component="Kết quả ML")
    if len(output) != len(normalized_events) or set(output_ids) != set(source_ids):
        raise ValueError("ML phải trả đúng một kết quả cho mỗi source_row_id đầu vào.")

    labels = pd.to_numeric(output["predicted_label"], errors="coerce")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("ML predicted_label chỉ được nhận giá trị 0 hoặc 1.")
    scores = pd.to_numeric(output["anomaly_score"], errors="coerce")
    if scores.isna().any() or not scores.map(math.isfinite).all() or not scores.between(0.0, 1.0).all():
        raise ValueError("ML anomaly_score phải là số hữu hạn trong khoảng [0, 1].")

    validated = output.copy()
    validated["source_row_id"] = output_ids
    validated["predicted_label"] = labels.astype("int64")
    validated["anomaly_score"] = scores.astype(float)
    return validated.reset_index(drop=True)


def _contains_rule(value):
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value) > 0
    if not isinstance(value, str) and pd.isna(value):
        return False
    if isinstance(value, str):
        return value.strip() not in {"", "[]", "()", "{}"}
    return bool(value)


def join_rule_ml_results(normalized_events, detected_logs, ml_results=None):
    """Join detector outputs one-to-one by source_row_id, preserving event order."""
    event_ids = validate_source_row_ids(normalized_events, component="Events")
    detected_ids = validate_source_row_ids(detected_logs, component="Rule results")
    if len(detected_logs) != len(normalized_events) or set(detected_ids) != set(event_ids):
        raise ValueError("Rule results phải khớp chính xác tập source_row_id của events.")

    event_order = pd.DataFrame({
        "source_row_id": event_ids.reset_index(drop=True),
        "_event_order": range(len(event_ids)),
    })
    rules = detected_logs.copy().reset_index(drop=True)
    rules["source_row_id"] = detected_ids.reset_index(drop=True)
    combined = event_order.merge(rules, on="source_row_id", how="left", validate="one_to_one", sort=False)
    combined = combined.sort_values("_event_order", kind="stable").drop(columns="_event_order").reset_index(drop=True)
    combined["Rule Alert"] = (
        combined["rule_ids"].map(_contains_rule)
        if "rule_ids" in combined
        else False
    )

    if ml_results is None:
        ml = pd.DataFrame(
            {
                "source_row_id": pd.Series(dtype="string"),
                "predicted_label": pd.Series(dtype="int64"),
                "anomaly_score": pd.Series(dtype="float64"),
            }
        )
    else:
        required = {"source_row_id", "predicted_label", "anomaly_score"}
        missing = sorted(required - set(ml_results.columns))
        if missing:
            raise ValueError("ML thiếu cột đầu ra: " + ", ".join(missing))
        ml = ml_results[["source_row_id", "predicted_label", "anomaly_score"]].copy()
        ml["source_row_id"] = validate_source_row_ids(ml, component="Kết quả ML").reset_index(drop=True)
        if not set(ml["source_row_id"]).issubset(set(event_ids)):
            raise ValueError("Kết quả ML chứa source_row_id không thuộc tập events.")
        labels = pd.to_numeric(ml["predicted_label"], errors="coerce")
        scores = pd.to_numeric(ml["anomaly_score"], errors="coerce")
        if (labels.isna().any() or not labels.isin([0, 1]).all()
                or scores.isna().any() or not scores.map(math.isfinite).all()
                or not scores.between(0.0, 1.0).all()):
            raise ValueError("Kết quả ML có predicted_label hoặc anomaly_score không hợp lệ.")
        ml["predicted_label"] = labels.astype("int64")
        ml["anomaly_score"] = scores.astype(float)

    combined = combined.merge(ml, on="source_row_id", how="left", validate="one_to_one", sort=False)
    evaluated = combined["predicted_label"].notna() & combined["anomaly_score"].notna()
    combined["ML Prediction"] = "Not Evaluated"
    combined.loc[evaluated & combined["predicted_label"].eq(0), "ML Prediction"] = "Normal"
    combined.loc[evaluated & combined["predicted_label"].eq(1), "ML Prediction"] = "Anomaly"
    combined["Comparison Group"] = "Not Evaluated"
    combined.loc[evaluated & ~combined["Rule Alert"] & combined["predicted_label"].eq(0), "Comparison Group"] = "Neither"
    combined.loc[evaluated & combined["Rule Alert"] & combined["predicted_label"].eq(0), "Comparison Group"] = "Rule Only"
    combined.loc[evaluated & ~combined["Rule Alert"] & combined["predicted_label"].eq(1), "Comparison Group"] = "ML Only"
    combined.loc[evaluated & combined["Rule Alert"] & combined["predicted_label"].eq(1), "Comparison Group"] = "Both"
    return combined


EVENT_FILTERS = (
    "All Events",
    "ML Anomaly Only",
    "Rule Alerts Only",
    "Both Rule and ML",
    "ML Only",
    "Rule Only",
    "Neither",
    "Not Evaluated",
)


def filter_dashboard_events(
    events,
    *,
    comparison_filter="All Events",
    activities=(),
    users=(),
    agents=(),
    include_missing_user=False,
):
    """Apply display-only filters to already evaluated event rows."""
    if comparison_filter not in EVENT_FILTERS:
        raise ValueError(f"Bộ lọc event không được hỗ trợ: {comparison_filter}")
    mask = pd.Series(True, index=events.index)
    if comparison_filter == "ML Anomaly Only":
        mask &= events["ML Prediction"].eq("Anomaly")
    elif comparison_filter == "Rule Alerts Only":
        mask &= events["Rule Alert"]
    elif comparison_filter == "Both Rule and ML":
        mask &= events["Comparison Group"].eq("Both")
    elif comparison_filter in {"ML Only", "Rule Only", "Neither", "Not Evaluated"}:
        mask &= events["Comparison Group"].eq(comparison_filter)
    if activities:
        mask &= events["Activity"].isin(activities)
    if users:
        user_mask = events["User"].isin(users)
        if include_missing_user:
            user_mask |= events["User"].isna()
        mask &= user_mask
    if agents:
        mask &= events["Agent_name"].isin(agents)
    return events.loc[mask].copy()
