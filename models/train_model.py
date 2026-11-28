"""Train ML pipelines from the normalized data bundle."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from preprocessing.data_bundle import load_table
from detection.ml_engine import (
    BEHAVIORAL_FEATURE_COLUMNS,
    FULL_FEATURE_COLUMNS,
    prepare_ml_input,
)


PROJECT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_DIR / "data" / "processed"
REPORT_DIR = PROJECT_DIR / "reports" / "ml"
MODEL_DIR = PROJECT_DIR / "models" / "artifacts"

RANDOM_STATE = 42
TEST_FRACTION = 0.20
VALIDATION_FRACTION_OF_TRAIN = 0.20


def load_training_data() -> pd.DataFrame:
    """Load the normalized event table and prepare causal ML features."""
    df = load_table("normalized_logs.csv", base_dir=DATA_DIR)
    if "Anomaly" not in df.columns:
        raise ValueError("normalized_logs.csv thiếu cột target Anomaly.")

    labels = df["Anomaly"].astype("string").str.strip()
    invalid_labels = sorted(set(labels.dropna().unique()) - {"0", "1"})
    if invalid_labels or labels.isna().any():
        raise ValueError(
            "Anomaly chỉ được chứa 0/1 và không được thiếu; "
            f"giá trị không hợp lệ: {invalid_labels}"
        )

    prepared = prepare_ml_input(df)
    prepared["Anomaly"] = (
        prepared["Anomaly"].astype("string").str.strip().astype("int8")
    )
    return prepared


def temporal_split(df: pd.DataFrame):
    """Use the latest 20% for test; earlier data for train/validation."""
    ordered = df.sort_values(
        ["Timestamp", "record_index"] if "record_index" in df.columns else ["Timestamp"],
        kind="stable",
    ).reset_index(drop=True)
    test_start = int(len(ordered) * (1 - TEST_FRACTION))
    train_validation = ordered.iloc[:test_start].copy()
    test = ordered.iloc[test_start:].copy()

    validation_start = int(
        len(train_validation) * (1 - VALIDATION_FRACTION_OF_TRAIN)
    )
    train = train_validation.iloc[:validation_start].copy()
    validation = train_validation.iloc[validation_start:].copy()
    return train, validation, test


def build_pipeline(model, feature_columns: list[str]) -> Pipeline:
    numeric_features = [
        column
        for column in [
            "hour",
            "User_events_15min_past",
            "Agent_name_events_15min_past",
        ]
        if column in feature_columns
    ]
    categorical_features = [
        column
        for column in [
            "day_of_week",
            "Activity",
            "Action",
            "Decoder_name",
            "User",
            "Agent_name",
        ]
        if column in feature_columns
    ]

    transformers = []
    if numeric_features:
        transformers.append(
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                numeric_features,
            )
        )
    if categorical_features:
        transformers.append(
            (
                "categorical",
                Pipeline(
                    steps=[
                        (
                            "imputer",
                            SimpleImputer(strategy="constant", fill_value="Unknown"),
                        ),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_features,
            )
        )

    return Pipeline(
        steps=[
            ("preprocessing", ColumnTransformer(transformers=transformers)),
            ("model", model),
        ]
    )


def select_f1_threshold(y_true, probabilities) -> tuple[float, float]:
    precision, recall, thresholds = precision_recall_curve(y_true, probabilities)
    if len(thresholds) == 0:
        return 0.5, float(f1_score(y_true, probabilities >= 0.5, zero_division=0))

    f1_values = (
        2 * precision[:-1] * recall[:-1]
        / np.maximum(precision[:-1] + recall[:-1], np.finfo(float).eps)
    )
    best_index = int(np.argmax(f1_values))
    return float(thresholds[best_index]), float(f1_values[best_index])


def calculate_metrics(y_true, probabilities, threshold: float) -> dict:
    predicted = (probabilities >= threshold).astype("int8")
    return {
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
    }


def save_confusion_matrix(y_true, probabilities, threshold, model_name: str) -> None:
    predicted = (probabilities >= threshold).astype("int8")
    fig, axis = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_predictions(
        y_true,
        predicted,
        display_labels=["Normal (0)", "Anomaly (1)"],
        values_format="d",
        cmap="Blues",
        colorbar=False,
        ax=axis,
    )
    axis.set_title(f"{model_name} (threshold={threshold:.3f})")
    fig.tight_layout()
    fig.savefig(
        REPORT_DIR / f"{model_name.lower().replace(' ', '_')}_confusion_matrix.png",
        dpi=150,
    )
    plt.close(fig)


def save_test_errors(test: pd.DataFrame, probabilities, threshold, model_key: str) -> None:
    result = test[
        [
            column
            for column in [
                "source_row_id",
                "Timestamp",
                "User",
                "Agent_name",
                "Activity",
                "Action",
                "Anomaly",
            ]
            if column in test.columns
        ]
    ].copy()
    result["anomaly_score"] = probabilities
    result["predicted_label"] = (probabilities >= threshold).astype("int8")

    for label, name in [(1, "false_negatives"), (0, "false_positives")]:
        if label == 1:
            errors = result[
                (result["Anomaly"] == 1) & (result["predicted_label"] == 0)
            ]
        else:
            errors = result[
                (result["Anomaly"] == 0) & (result["predicted_label"] == 1)
            ]
        errors.to_csv(REPORT_DIR / f"{model_key}_{name}.csv", index=False)


def train_model(
    model_name: str,
    model_key: str,
    estimator,
    feature_columns: list[str],
    train: pd.DataFrame,
    validation: pd.DataFrame,
    test: pd.DataFrame,
) -> dict:
    model = build_pipeline(estimator, feature_columns)
    model.fit(train[feature_columns], train["Anomaly"])

    validation_probabilities = model.predict_proba(validation[feature_columns])[:, 1]
    threshold, validation_f1 = select_f1_threshold(
        validation["Anomaly"],
        validation_probabilities,
    )

    test_probabilities = model.predict_proba(test[feature_columns])[:, 1]
    metrics = calculate_metrics(test["Anomaly"], test_probabilities, threshold)
    metrics.update(
        {
            "model": model_name,
            "model_key": model_key,
            "feature_set": ", ".join(feature_columns),
            "validation_threshold": threshold,
            "validation_f1": validation_f1,
            "test_rows": int(len(test)),
        }
    )

    save_confusion_matrix(test["Anomaly"], test_probabilities, threshold, model_key)
    save_test_errors(test, test_probabilities, threshold, model_key)

    # Refit the preprocessing/model pipeline on all pre-test data after selecting
    # the threshold on the earlier validation window.
    final_model = build_pipeline(estimator, feature_columns)
    pre_test = pd.concat([train, validation], ignore_index=True)
    final_model.fit(pre_test[feature_columns], pre_test["Anomaly"])
    joblib.dump(final_model, MODEL_DIR / f"{model_key}.joblib")
    return metrics


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    data_path = DATA_DIR / "normalized_logs.csv"
    df = load_training_data()
    train, validation, test = temporal_split(df)
    if train["Anomaly"].nunique() < 2 or validation["Anomaly"].nunique() < 2:
        raise ValueError("Train và validation phải cùng chứa cả hai lớp Anomaly.")

    models = [
        (
            "Logistic Regression",
            "logistic_regression",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
            FULL_FEATURE_COLUMNS,
        ),
        (
            "Random Forest",
            "random_forest",
            RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
            FULL_FEATURE_COLUMNS,
        ),
        (
            "Random Forest Behavioral",
            "random_forest_behavioral",
            RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
            BEHAVIORAL_FEATURE_COLUMNS,
        ),
    ]

    results = [
        train_model(
            model_name,
            model_key,
            estimator,
            feature_columns,
            train,
            validation,
            test,
        )
        for model_name, model_key, estimator, feature_columns in models
    ]
    pd.DataFrame(results).to_csv(REPORT_DIR / "model_metrics.csv", index=False)
    with (REPORT_DIR / "model_metrics.json").open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)
    thresholds = {
        f"{result['model_key']}.joblib": result["validation_threshold"]
        for result in results
    }
    with (REPORT_DIR / "model_thresholds.json").open("w", encoding="utf-8") as file:
        json.dump(thresholds, file, indent=2)

    manifest = {
        "dataset": "data/processed/normalized_logs.csv",
        "dataset_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
        "rows": int(len(df)),
        "train_rows": int(len(train)),
        "validation_rows": int(len(validation)),
        "test_rows": int(len(test)),
        "train_timestamp_range": [
            str(train["Timestamp"].min()),
            str(train["Timestamp"].max()),
        ],
        "validation_timestamp_range": [
            str(validation["Timestamp"].min()),
            str(validation["Timestamp"].max()),
        ],
        "test_timestamp_range": [
            str(test["Timestamp"].min()),
            str(test["Timestamp"].max()),
        ],
        "train_target_distribution": train["Anomaly"].value_counts().sort_index().to_dict(),
        "validation_target_distribution": validation["Anomaly"].value_counts().sort_index().to_dict(),
        "test_target_distribution": test["Anomaly"].value_counts().sort_index().to_dict(),
        "random_state": RANDOM_STATE,
        "split_strategy": "chronological 64% train / 16% validation / 20% test",
        "window": "15min; counts prior timestamps only, current timestamp excluded",
        "models": results,
    }
    with (REPORT_DIR / "training_manifest.json").open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)

    print("Dataset:", data_path)
    print(
        "Rows:",
        len(df),
        "| train:",
        len(train),
        "| validation:",
        len(validation),
        "| test:",
        len(test),
    )
    print(pd.DataFrame(results).to_string(index=False))
    print("Saved artifacts to:", MODEL_DIR)
    print("Saved reports to:", REPORT_DIR)


if __name__ == "__main__":
    main()
