import copy
from io import BytesIO
from pathlib import Path
import tempfile
import unittest

import pandas as pd

from dashboard.service import run_upload_pipeline
from detection.pipeline import PipelineError, run_detection_pipeline
from detection.severity import load_severity_config
from detection.severity import assign_severity
from preprocessing.detected_io import save_detected_logs, read_detected_logs
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize


def csv_bytes(count=4, command="nmap"):
    return pd.DataFrame({"id": list(range(count)), "Timestamp": [f"2025-03-06 12:00:{i:02d}.123" for i in range(count)],
                         "User": ["Alice"]*count, "Agent_name": ["Host"]*count, "Activity": ["Command"]*count,
                         "Action": ["command executed"]*count, "Command": [command]*count, "Path": [""]*count,
                         "Url": [""]*count, "Full_log": [' Raw "quoted",\r\n ']*count,
                         "Description": ["NA"]*count, "Content": [""]*count}).to_csv(index=False).encode("utf-8")


class PipelineTests(unittest.TestCase):
    def normalized(self, count=4, command="nmap"):
        return normalize(load_logs(BytesIO(csv_bytes(count, command))))

    def test_end_to_end_upload_and_current_event_features(self):
        result = run_upload_pipeline(BytesIO(csv_bytes()))
        self.assertEqual(result["status"], "success")
        frame = result["detected_logs"]
        self.assertEqual(frame.alert_count.tolist(), [1]*4)
        self.assertEqual(frame.rule_ids.tolist(), [["CMD_NMAP"]]*4)
        self.assertEqual(frame.severity.tolist(), ["MEDIUM", "MEDIUM", "HIGH", "HIGH"])
        self.assertEqual(frame.group_id.nunique(), 1)
        self.assertEqual(len(result["alerts"]), 4)
        self.assertTrue(all(value >= 0 for value in result["report"]["timings_seconds"].values()))

    def test_join_source_id_preserves_input_order_index_and_raw(self):
        frame = self.normalized().iloc[::-1].copy()
        frame.index = [9, 9, 7, 8]
        before = frame.copy(deep=True)
        result = run_detection_pipeline(frame)["detected_logs"]
        pd.testing.assert_frame_equal(result[before.columns], before)
        self.assertEqual(result.severity.tolist(), ["HIGH", "HIGH", "MEDIUM", "MEDIUM"])

    def test_no_alert_is_success_zero_count_null_severity(self):
        result = run_detection_pipeline(self.normalized(command="ls"))
        self.assertEqual(result["alerts"], [])
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["detected_logs"].alert_count.tolist(), [0]*4)
        self.assertTrue(result["detected_logs"].severity.isna().all())

    def test_empty_normalized_input(self):
        result = run_detection_pipeline(self.normalized().iloc[:0])
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["detected_logs"].empty)
        self.assertEqual(str(result["detected_logs"].alert_count.dtype), "Int64")

    def test_missing_user_or_invalid_timestamp_keep_source_row(self):
        frame = self.normalized()
        frame.loc[0, "User"] = pd.NA
        frame.loc[1, "Timestamp"] = pd.NaT
        frame.loc[1, "invalid_timestamp"] = True
        result = run_detection_pipeline(frame)["detected_logs"]
        self.assertEqual(len(result), 4)
        self.assertTrue(result.group_id.iloc[:2].isna().all())
        self.assertEqual(result.alert_count.tolist(), [1, 0, 1, 1])
        self.assertTrue(pd.isna(result.severity.iloc[1]))

    def test_schema_errors_expose_stage_not_empty_success(self):
        for column in ("source_row_id", "Command", "Url", "Timestamp"):
            with self.subTest(column=column), self.assertRaises(PipelineError) as caught:
                run_detection_pipeline(self.normalized().drop(columns=column))
            self.assertEqual(caught.exception.report["status"], "error")
            self.assertIn(column, str(caught.exception))
        with self.assertRaisesRegex(PipelineError, "detection"):
            run_detection_pipeline(run_detection_pipeline(self.normalized())["detected_logs"])

    def test_duplicate_source_and_wrong_timestamp_dtype_raise(self):
        frame = self.normalized()
        frame["source_row_id"] = frame.source_row_id.iloc[0]
        with self.assertRaises(PipelineError): run_detection_pipeline(frame)
        frame = self.normalized()
        frame["Timestamp"] = frame.Timestamp.astype("string")
        with self.assertRaises(PipelineError): run_detection_pipeline(frame)

    def test_future_features_unchanged_including_equal_timestamp_ties(self):
        frame = self.normalized()
        frame["Timestamp"] = frame.Timestamp.iloc[0]
        early = run_detection_pipeline(frame.iloc[:2])["detected_logs"]
        full = run_detection_pipeline(frame)["detected_logs"]
        pd.testing.assert_frame_equal(early, full.iloc[:2], check_flags=False)

    def test_label_Level_independent_input_not_mutated(self):
        frame = self.normalized()
        before = frame.copy(deep=True)
        baseline = run_detection_pipeline(frame)
        pd.testing.assert_frame_equal(frame, before)
        frame["Anomaly"], frame["Level"] = "not a feature", 999
        result = run_detection_pipeline(frame)
        self.assertEqual(result["alerts"], baseline["alerts"])
        for column in ("rule_ids", "alert_count", "group_id", "severity"):
            pd.testing.assert_series_equal(result["detected_logs"][column], baseline["detected_logs"][column])

    def test_min_events_filter_rejected_for_causal_features(self):
        policy = load_severity_config()
        policy["correlation"]["min_events"] = 3
        with self.assertRaisesRegex(PipelineError, "min_events=1"):
            run_detection_pipeline(self.normalized(), severity_config=policy)

    def test_reused_canonical_groups_match_public_severity_validation(self):
        frame = self.normalized()
        result = run_detection_pipeline(frame)
        self.assertEqual(result["atomic_alerts"], assign_severity(result["atomic_alerts"], result["groups"], events=frame))

    def test_detected_csv_round_trip_raw_null_json_and_checksums(self):
        frame = run_detection_pipeline(self.normalized())["detected_logs"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"detected.csv"
            save_detected_logs(frame, path)
            restored = read_detected_logs(path)
            pd.testing.assert_frame_equal(frame, restored)
            self.assertEqual(frame.attrs, restored.attrs)
            path.write_bytes(path.read_bytes()+b"tampered")
            with self.assertRaisesRegex(ValueError, "Checksum"): read_detected_logs(path)

    def test_detected_export_does_not_overwrite_unknown_target(self):
        frame = run_detection_pipeline(self.normalized())["detected_logs"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"original.csv"
            path.write_bytes(b"original")
            with self.assertRaises(ValueError): save_detected_logs(frame, path)
            self.assertEqual(path.read_bytes(), b"original")

    def test_empty_and_zero_alert_detected_csv_round_trip(self):
        for frame in (self.normalized().iloc[:0], self.normalized(command="ls")):
            detected = run_detection_pipeline(frame)["detected_logs"]
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/"detected.csv"
                save_detected_logs(detected, path)
                pd.testing.assert_frame_equal(detected, read_detected_logs(path))


if __name__ == "__main__":
    unittest.main()
