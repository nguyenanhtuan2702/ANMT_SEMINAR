from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from detection.ml_engine import make_source_row_ids, predict, prepare_ml_input


class MlEngineTest(unittest.TestCase):
    def setUp(self):
        self.df = pd.DataFrame(
            [
                {
                    "id": "alternate-event-1",
                    "source_row_id": "source-event-1",
                    "Timestamp": "2025-03-30 10:00:00",
                    "User": "alice",
                    "Agent_name": "host-a",
                    "Activity": "http",
                    "Action": "URL accedida",
                    "Decoder_name": "cert",
                },
                {
                    "id": "alternate-event-2",
                    "source_row_id": "source-event-2",
                    "Timestamp": "2025-03-30 10:01:00",
                    "User": "alice",
                    "Agent_name": "host-a",
                    "Activity": "http",
                    "Action": "URL accedida",
                    "Decoder_name": "cert",
                },
            ]
        )

    def test_window_uses_only_prior_rows(self):
        prepared = prepare_ml_input(self.df)
        self.assertEqual(prepared.loc[0, "User_events_15min_past"], 0)
        self.assertEqual(prepared.loc[1, "User_events_15min_past"], 1)
        self.assertEqual(prepared.loc[1, "Agent_name_events_15min_past"], 1)

    def test_inference_contract_columns(self):
        result = predict(
            self.df,
            model_name="random_forest_behavioral.joblib",
            threshold=0.52,
        )
        expected = {
            "source_row_id",
            "timestamp",
            "user",
            "agent",
            "activity",
            "action",
            "predicted_label",
            "anomaly_score",
        }
        self.assertEqual(set(result.columns), expected)
        self.assertEqual(
            result["source_row_id"].tolist(),
            ["source-event-1", "source-event-2"],
        )
        self.assertTrue(result["anomaly_score"].between(0.0, 1.0).all())

    def test_source_row_ids_are_required_and_validated(self):
        invalid_frames = [
            self.df.drop(columns="source_row_id"),
            self.df.assign(source_row_id=[None, "source-event-2"]),
            self.df.assign(source_row_id=[" ", "source-event-2"]),
            self.df.assign(source_row_id=["duplicate", "duplicate"]),
        ]
        for frame in invalid_frames:
            with self.subTest(source_ids=frame.get("source_row_id")):
                with self.assertRaisesRegex(ValueError, "source_row_id"):
                    make_source_row_ids(frame)

    def test_source_ids_are_not_replaced_by_id_or_generated_ids(self):
        frame = self.df.drop(columns="source_row_id")
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            make_source_row_ids(frame)

    def test_threshold_controls_classification_of_class_one_score(self):
        class FixedProbabilityModel:
            classes_ = np.array([0, 1])

            def predict_proba(self, features):
                return np.array([[0.8, 0.2], [0.35, 0.65]])

        with patch(
            "detection.ml_engine.joblib.load",
            return_value=FixedProbabilityModel(),
        ):
            at_half = predict(self.df, threshold=0.5)
            at_point_seven = predict(self.df, threshold=0.7)

        self.assertEqual(at_half["predicted_label"].tolist(), [0, 1])
        self.assertEqual(at_point_seven["predicted_label"].tolist(), [0, 0])
        self.assertEqual(at_half["anomaly_score"].tolist(), [0.2, 0.65])

    def test_all_model_artifacts_load_with_normal_class_contract(self):
        model_names = [
            "logistic_regression.joblib",
            "random_forest.joblib",
            "random_forest_behavioral.joblib",
        ]
        for model_name in model_names:
            with self.subTest(model=model_name):
                result = predict(self.df, model_name=model_name, threshold=0.5)
                self.assertEqual(len(result), len(self.df))
                self.assertEqual(
                    result["source_row_id"].tolist(),
                    ["source-event-1", "source-event-2"],
                )
                self.assertTrue(result["anomaly_score"].between(0.0, 1.0).all())
                self.assertTrue(
                    (
                        result["predicted_label"]
                        == (result["anomaly_score"] >= 0.5).astype(int)
                    ).all()
                )

    def test_missing_anomaly_is_allowed(self):
        result = predict(
            self.df,
            model_name="random_forest_behavioral.joblib",
        )
        self.assertEqual(len(result), len(self.df))

    def test_features_match_normalized_log_conventions(self):
        source = self.df.copy()
        source.loc[0, "Action"] = " URL ACCEDIDA "
        source.loc[0, "User"] = None
        source.loc[1, "User"] = None
        prepared = prepare_ml_input(source)

        self.assertEqual(prepared.loc[0, "day_of_week"], "6")
        self.assertEqual(prepared.loc[0, "Action"], "url accedida")
        self.assertEqual(prepared.loc[0, "User_events_15min_past"], 0)
        self.assertEqual(prepared.loc[1, "User_events_15min_past"], 0)
        self.assertEqual(prepared.loc[1, "Agent_name_events_15min_past"], 1)


class TrainingDataTest(unittest.TestCase):
    def test_loads_normalized_bundle_with_integer_target(self):
        from models.train_model import load_training_data, temporal_split

        df = load_training_data()
        train, validation, test = temporal_split(df)

        self.assertEqual(len(df), 72250)
        self.assertTrue(set(df["Anomaly"].unique()).issubset({0, 1}))
        self.assertTrue(df["source_row_id"].is_unique)
        self.assertLess(train["Timestamp"].max(), validation["Timestamp"].min())
        self.assertLess(validation["Timestamp"].max(), test["Timestamp"].min())


if __name__ == "__main__":
    unittest.main()
