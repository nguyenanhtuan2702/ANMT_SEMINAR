"""Shared normalization API, lossless CSV export and dashboard sample."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

import pandas as pd

from preprocessing.export_normalized_dataset import dashboard_sample
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize, normalize_logs
from preprocessing.normalized_io import read_normalized_logs, save_normalized_logs


class NormalizedIOTests(unittest.TestCase):
    def events(self, labeled=True):
        columns = ["id", "Timestamp", "User", "Agent_name", "Activity", "Action", "Decoder_name", "Full_log", "Description", "Content", "Size_before"]
        if labeled:
            columns.append("Anomaly")
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for i in range(12):
            row = {"id": str(i), "Timestamp": "bad" if i == 11 else f"2025-03-06 12:00:{i:02d}.123",
                   "User": "" if i == 0 else " Alice ", "Agent_name": " HOST ",
                   "Activity": " FILE " if i%2 else " COMMAND ", "Action": " File Modified ",
                   "Decoder_name": " AuditD ", "Full_log": ' NA, "Mixed"\r\nraw\n ',
                   "Description": "", "Content": "__SPEDIA_NULL__" if i == 0 else "NA",
                   "Size_before": "-5.0" if i == 0 else ""}
            if labeled:
                row["Anomaly"] = "1" if i%2 else "0"
            writer.writerow(row)
        return normalize(load_logs(io.BytesIO(stream.getvalue().encode("utf-8"))))

    def test_normalize_is_exact_same_training_and_inference_function(self):
        self.assertIs(normalize, normalize_logs)
        events = self.events(labeled=False)
        self.assertNotIn("Anomaly", events)
        self.assertEqual(len(events), 12)
        self.assertTrue(events.invalid_timestamp.iloc[-1])
        pd.testing.assert_frame_equal(normalize(events), events)

    def test_csv_round_trip_dtypes_raw_empty_null_marker_collision_and_attrs(self):
        events = self.events()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"normalized.csv"
            metadata = save_normalized_logs(events, path)
            restored = read_normalized_logs(path)
            self.assertNotEqual(metadata["null_marker"], "__SPEDIA_NULL__")
            pd.testing.assert_frame_equal(events, restored, check_exact=True)
            self.assertEqual(events.attrs, restored.attrs)
            self.assertEqual(restored.Description.iloc[0], "")
            self.assertTrue(pd.isna(restored.User.iloc[0]))
            self.assertEqual(restored.Content.iloc[0], "__SPEDIA_NULL__")
            self.assertEqual(restored.Content.iloc[1], "NA")
            pd.testing.assert_frame_equal(normalize(restored), restored, check_exact=True)

    def test_missing_or_stale_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"normalized.csv"
            path.write_text("dummy", encoding="utf-8")
            with self.assertRaisesRegex(FileNotFoundError, "metadata"):
                read_normalized_logs(path)
            save_normalized_logs(self.events(), path)
            with path.open("ab") as stream:
                stream.write(b"extra")
            with self.assertRaisesRegex(ValueError, "Checksum"):
                read_normalized_logs(path)

    def test_empty_normalized_frame_round_trip(self):
        events = normalize(self.events().iloc[:0])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"empty.csv"
            save_normalized_logs(events, path)
            pd.testing.assert_frame_equal(read_normalized_logs(path), events, check_exact=True)

    def test_float64_round_trip_exact_for_noninteger_values(self):
        events = self.events()
        events["transport_float"] = pd.Series([0.12345678912345678, 1.2345678901234567, 1e-200, 1e200]*3, dtype="Float64")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"numeric.csv"
            save_normalized_logs(events, path)
            pd.testing.assert_frame_equal(read_normalized_logs(path), events, check_exact=True)

    def test_writer_rejects_raw_frame_duplicate_keys_and_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"normalized.csv"
            with self.assertRaises(ValueError):
                save_normalized_logs(pd.DataFrame({"Timestamp": ["bad"]}), path)
            source = self.events()
            source["source_row_id"] = "duplicate"
            with self.assertRaisesRegex(ValueError, "source_row_id"):
                save_normalized_logs(source, path)
            with self.assertRaisesRegex(ValueError, "csv"):
                save_normalized_logs(self.events(), path.with_suffix(".parquet"))

    def test_sample_preserves_ids_covers_activities_and_is_reproducible(self):
        events = self.events()
        first = dashboard_sample(events, size=6, seed=42)
        second = dashboard_sample(events, size=6, seed=42)
        self.assertEqual(len(first), 6)
        self.assertEqual(set(first.Activity), set(events.Activity))
        self.assertTrue(set(first.source_row_id).issubset(set(events.source_row_id)))
        self.assertEqual(first.attrs["normalization_report"]["rows_output"], 6)
        pd.testing.assert_frame_equal(first, second)

    def test_sample_label_independent_and_too_small_rejected(self):
        source = self.events()
        selected = dashboard_sample(source, size=6).source_row_id.tolist()
        source["Anomaly"] = "anything"
        self.assertEqual(dashboard_sample(source, size=6).source_row_id.tolist(), selected)
        with self.assertRaises(ValueError):
            dashboard_sample(source, size=1)

    def test_inference_export_works_without_label_and_restores_metadata(self):
        source = self.events(labeled=False)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"inference.csv"
            save_normalized_logs(source, path)
            restored = read_normalized_logs(path)
            self.assertNotIn("Anomaly", restored)
            self.assertEqual(json.loads(path.with_suffix(".schema.json").read_text(encoding="utf-8"))["row_count"], 12)
            self.assertEqual(restored.source_row_id.tolist(), source.source_row_id.tolist())


if __name__ == "__main__":
    unittest.main()
