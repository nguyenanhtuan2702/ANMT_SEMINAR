"""Service-level checks for independent Rule/ML dashboard integration."""
from io import BytesIO
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

import pandas as pd

from dashboard.service import (
    DEFAULT_THRESHOLD,
    MODEL_DIR,
    filter_dashboard_events,
    join_rule_ml_results,
    model_artifact_version,
    resolve_model_threshold,
    run_ml_inference,
    run_upload_pipeline,
)


def event_frame():
    return pd.DataFrame(
        {
            "source_row_id": [f"file:{index:08d}" for index in range(5)],
            "record_index": range(5),
            "Timestamp": pd.date_range("2025-03-06 12:00:00", periods=5, freq="min"),
            "User": ["alice", "alice", "bob", "bob", None],
            "Agent_name": ["host-a", "host-a", "host-b", "host-b", "host-a"],
            "Activity": ["command", "command", "http", "http", "other"],
            "Action": ["command executed"] * 5,
            "Decoder_name": ["test"] * 5,
            "Anomaly": [1, 0, 1, 0, 0],
            "Level": [1, 2, 3, 4, 5],
        }
    )


def rule_frame():
    frame = event_frame().drop(columns=["Anomaly", "Level"]).copy()
    frame["rule_ids"] = [["R1"], ["R1"], [], [], ["R2"]]
    frame["severity"] = ["MEDIUM", "HIGH", None, None, "LOW"]
    return frame


class DashboardServiceTests(unittest.TestCase):
    def test_ml_input_drops_reference_labels_and_checks_complete_keys(self):
        frame = event_frame()
        expected = pd.DataFrame(
            {
                "source_row_id": frame["source_row_id"],
                "predicted_label": [0, 1, 0, 1, 0],
                "anomaly_score": [0.1, 0.9, 0.2, 0.8, 0.05],
            }
        )
        mock_module = ModuleType("detection.ml_engine")
        mock_module.predict = Mock(return_value=expected)
        with patch.dict(sys.modules, {"detection.ml_engine": mock_module}):
            output = run_ml_inference(frame, "random_forest_behavioral.joblib", 0.52)

        ml_input = mock_module.predict.call_args.args[0]
        self.assertNotIn("Anomaly", ml_input.columns)
        self.assertNotIn("Level", ml_input.columns)
        self.assertEqual(output["source_row_id"].tolist(), frame["source_row_id"].tolist())
        self.assertEqual(len(output), len(frame))

    def test_ml_rejects_missing_duplicate_or_unknown_output_ids(self):
        frame = event_frame()
        invalid_outputs = [
            pd.DataFrame({"predicted_label": [0], "anomaly_score": [0.1]}),
            pd.DataFrame({"source_row_id": ["file:00000000"] * 5, "predicted_label": [0] * 5, "anomaly_score": [0.1] * 5}),
            pd.DataFrame({"source_row_id": ["elsewhere"] * 5, "predicted_label": [0] * 5, "anomaly_score": [0.1] * 5}),
        ]
        for output in invalid_outputs:
            mock_module = ModuleType("detection.ml_engine")
            mock_module.predict = Mock(return_value=output)
            with self.subTest(columns=list(output.columns)), patch.dict(sys.modules, {"detection.ml_engine": mock_module}):
                with self.assertRaises(ValueError):
                    run_ml_inference(frame, "random_forest_behavioral.joblib", 0.52)

    def test_ml_requires_nonempty_unique_input_source_ids(self):
        frames = [
            event_frame().drop(columns="source_row_id"),
            event_frame().assign(source_row_id=["duplicate"] * 5),
            event_frame().assign(source_row_id=[" ", "id-1", "id-2", "id-3", "id-4"]),
        ]
        for frame in frames:
            with self.subTest(ids=frame.get("source_row_id")), self.assertRaisesRegex(ValueError, "source_row_id"):
                run_ml_inference(frame, "random_forest_behavioral.joblib", 0.52)

    def test_join_creates_four_groups_and_keeps_missing_prediction_distinct(self):
        events = event_frame()
        predictions = pd.DataFrame(
            {
                "source_row_id": events.source_row_id.iloc[:4],
                "predicted_label": [1, 0, 1, 0],
                "anomaly_score": [0.9, 0.2, 0.8, 0.1],
            }
        )
        combined = join_rule_ml_results(events, rule_frame(), predictions)

        self.assertEqual(combined["Comparison Group"].tolist(), ["Both", "Rule Only", "ML Only", "Neither", "Not Evaluated"])
        self.assertEqual(combined["ML Prediction"].tolist(), ["Anomaly", "Normal", "Anomaly", "Normal", "Not Evaluated"])
        self.assertEqual(combined["severity"].iloc[[0, 1, 4]].tolist(), ["MEDIUM", "HIGH", "LOW"])
        self.assertTrue(combined["severity"].iloc[[2, 3]].isna().all())
        self.assertEqual(len(combined), len(events))

    def test_missing_ml_result_marks_every_event_not_evaluated(self):
        combined = join_rule_ml_results(event_frame(), rule_frame(), ml_results=None)
        self.assertTrue(combined["ML Prediction"].eq("Not Evaluated").all())
        self.assertTrue(combined["Comparison Group"].eq("Not Evaluated").all())

    def test_join_rejects_unknown_or_duplicate_ml_ids(self):
        events = event_frame()
        invalid = pd.DataFrame(
            {
                "source_row_id": ["unknown"],
                "predicted_label": [1],
                "anomaly_score": [0.8],
            }
        )
        with self.assertRaisesRegex(ValueError, "không thuộc"):
            join_rule_ml_results(events, rule_frame(), invalid)
        invalid.loc[1] = invalid.iloc[0]
        with self.assertRaisesRegex(ValueError, "duy nhất"):
            join_rule_ml_results(events, rule_frame(), invalid)

    def test_display_filters_compose_without_changing_inference_rows(self):
        events = event_frame()
        predictions = pd.DataFrame(
            {
                "source_row_id": events.source_row_id.iloc[:4],
                "predicted_label": [1, 0, 1, 0],
                "anomaly_score": [0.9, 0.2, 0.8, 0.1],
            }
        )
        combined = join_rule_ml_results(events, rule_frame(), predictions)
        both = filter_dashboard_events(combined, comparison_filter="Both Rule and ML")
        self.assertEqual(both.source_row_id.tolist(), ["file:00000000"])
        selected = filter_dashboard_events(combined, comparison_filter="ML Anomaly Only", activities=["http"])
        self.assertEqual(selected.source_row_id.tolist(), ["file:00000002"])
        missing_user = filter_dashboard_events(combined, users=["alice"], include_missing_user=True)
        self.assertEqual(len(missing_user), 3)
        self.assertEqual(len(combined), 5)

    def test_threshold_config_uses_values_or_notices_on_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "thresholds.json"
            config.write_text(json.dumps({"random_forest.joblib": 0.63}), encoding="utf-8")
            self.assertEqual(resolve_model_threshold("random_forest.joblib", config), (0.63, None))
            fallback, notice = resolve_model_threshold("logistic_regression.joblib", config)
            self.assertEqual(fallback, DEFAULT_THRESHOLD)
            self.assertIn("fallback", notice)

            config.write_text(json.dumps({"random_forest.joblib": True}), encoding="utf-8")
            fallback, notice = resolve_model_threshold("random_forest.joblib", config)
            self.assertEqual(fallback, DEFAULT_THRESHOLD)
            self.assertIsNotNone(notice)

            config.unlink()
            fallback, notice = resolve_model_threshold("random_forest.joblib", config)
            self.assertEqual(fallback, DEFAULT_THRESHOLD)
            self.assertIsNotNone(notice)

    def test_artifact_version_changes_when_model_file_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact_dir = Path(folder)
            artifact = artifact_dir / "random_forest.joblib"
            artifact.write_bytes(b"model-v1")
            with patch("dashboard.service.MODEL_DIR", artifact_dir):
                first = model_artifact_version("random_forest.joblib")
                artifact.write_bytes(b"model-v2-with-new-size")
                second = model_artifact_version("random_forest.joblib")
            self.assertNotEqual(first, second)

    def test_upload_service_retains_full_normalized_frame_for_inference(self):
        from test_pipeline import csv_bytes

        result = run_upload_pipeline(BytesIO(csv_bytes()))
        normalized = result["normalized_logs"]
        self.assertEqual(len(normalized), len(result["detected_logs"]))
        self.assertEqual(normalized.source_row_id.tolist(), result["detected_logs"].source_row_id.tolist())
        self.assertIn("Decoder_name", normalized.columns)


@unittest.skipUnless(
    importlib.util.find_spec("sklearn") is not None
    and (MODEL_DIR / "random_forest_behavioral.joblib").exists(),
    "Real ML integration requires scikit-learn and the behavioral model artifact.",
)
class RealDashboardInferenceTests(unittest.TestCase):
    def test_uploaded_pipeline_and_real_model_join_by_source_row_id(self):
        from test_pipeline import csv_bytes

        result = run_upload_pipeline(BytesIO(csv_bytes()))
        predictions = run_ml_inference(
            result["normalized_logs"],
            "random_forest_behavioral.joblib",
            0.18,
        )
        combined = join_rule_ml_results(result["normalized_logs"], result["detected_logs"], predictions)

        self.assertEqual(len(predictions), len(result["normalized_logs"]))
        self.assertEqual(combined.source_row_id.tolist(), result["normalized_logs"].source_row_id.tolist())
        self.assertNotIn("Not Evaluated", combined["ML Prediction"].tolist())


if __name__ == "__main__":
    unittest.main()
