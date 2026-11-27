from pathlib import Path
import sys
import unittest

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from detection.ml_engine import predict, prepare_ml_input


class MlEngineTest(unittest.TestCase):
    def setUp(self):
        self.df = pd.DataFrame(
            [
                {
                    "id": "event-1",
                    "Timestamp": "2025-03-30 10:00:00",
                    "User": "alice",
                    "Agent_name": "host-a",
                    "Activity": "http",
                    "Action": "URL accedida",
                    "Decoder_name": "cert",
                },
                {
                    "id": "event-2",
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
        self.assertEqual(result["source_row_id"].tolist(), ["event-1", "event-2"])
        self.assertTrue(result["anomaly_score"].between(0.0, 1.0).all())

    def test_missing_anomaly_is_allowed(self):
        result = predict(
            self.df,
            model_name="random_forest_behavioral.joblib",
        )
        self.assertEqual(len(result), len(self.df))


if __name__ == "__main__":
    unittest.main()
