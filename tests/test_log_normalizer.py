"""Event normalization: evidence, time errors, stable identity and chronology."""
import copy
import csv
import io
import unittest

import pandas as pd

from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import EVENT_COLUMNS, SOURCE_COLUMNS, normalize_logs

DIGEST = "a" * 64


class LogNormalizerTests(unittest.TestCase):
    def frame(self, timestamps=None):
        timestamps = timestamps if timestamps is not None else ["2025-03-06 13:15:10.797"]
        return pd.DataFrame({
            "id": [f"id-{i}" for i in range(len(timestamps))], "Timestamp": timestamps,
            "Activity": [" COMMAND "]*len(timestamps), "Action": [" Command EXECUTED "]*len(timestamps),
            "User": [" Irene "]*len(timestamps), "Agent_name": [" Public-HOST "]*len(timestamps),
            "Decoder_name": [" AuditD "]*len(timestamps),
            "source_row_id": [f"{DIGEST}:{i:08d}" for i in range(len(timestamps))],
            "record_index": list(range(len(timestamps))),
        })

    def test_timestamp_and_calendar_columns(self):
        normalized = normalize_logs(self.frame())
        self.assertEqual(str(normalized.Timestamp.dtype), "datetime64[ns]")
        self.assertEqual(normalized.Timestamp.iloc[0], pd.Timestamp("2025-03-06 13:15:10.797"))
        self.assertEqual(normalized.hour.iloc[0], 13)
        self.assertEqual(normalized.day_of_week.iloc[0], 3)
        self.assertEqual(normalized.date.iloc[0], pd.Timestamp("2025-03-06").date())
        self.assertIsNone(normalized.Timestamp.dt.tz)
        self.assertEqual(str(normalized.hour.dtype), "Int64")
        self.assertFalse(normalized.invalid_timestamp.any())

    def test_invalid_dates_formats_missing_and_timezone_are_flagged_not_dropped(self):
        source = self.frame(["bad", "2025-02-30 12:00:00.000", "", None,
                             "2025-03-06T12:00:00.000Z", "2025-03-06 12:00:00.000"])
        output = normalize_logs(source)
        self.assertEqual(len(output), 6)
        by_index = output.set_index("record_index")
        self.assertEqual(by_index.loc[list(range(5)), "timestamp_error"].tolist(),
                         ["invalid_format", "invalid_datetime", "missing_timestamp", "missing_timestamp", "invalid_format"])
        self.assertEqual(output.record_index.tolist(), [5, 0, 1, 2, 3, 4])
        self.assertEqual(int(output.invalid_timestamp.sum()), 5)
        self.assertTrue(output.loc[output.invalid_timestamp, "hour"].isna().all())
        self.assertTrue(output.loc[output.invalid_timestamp, "day_of_week"].isna().all())
        self.assertTrue(output.loc[output.invalid_timestamp, "date"].isna().all())
        self.assertEqual(output.attrs["normalization_report"]["rows_dropped"], 0)
        self.assertEqual(len(output.attrs["normalization_report"]["timestamp_issues"]), 5)

    def test_out_of_range_timestamp_is_flagged_without_crashing(self):
        output = normalize_logs(self.frame(["1500-01-01 00:00:00.000", "2500-01-01 00:00:00.000"]))
        self.assertTrue(output.invalid_timestamp.all())
        self.assertEqual(output.timestamp_error.tolist(), ["invalid_datetime", "invalid_datetime"])

    def test_chronological_sort_and_equal_time_use_original_record_index(self):
        source = self.frame(["2025-03-07 00:00:00.000", "2025-03-06 10:00:00.000", "2025-03-06 10:00:00.000"])
        source = source.iloc[[2, 0, 1]].copy()
        result = normalize_logs(source)
        self.assertEqual(result.record_index.tolist(), [1, 2, 0])
        self.assertEqual(result.source_row_id.tolist(), [f"{DIGEST}:{i:08d}" for i in [1, 2, 0]])
        self.assertTrue(result.Timestamp.is_monotonic_increasing)

    def test_text_normalization_preserves_originals_and_does_not_translate(self):
        source = self.frame()
        source.loc[0, "Action"] = " URL accedida "
        result = normalize_logs(source)
        for column, expected in {"Activity": "command", "Action": "url accedida", "User": "irene", "Agent_name": "public-host", "Decoder_name": "auditd"}.items():
            self.assertEqual(result.at[0, column], expected)
            self.assertEqual(result.at[0, column+"_raw"], source.at[0, column])

    def test_missing_text_stays_missing_and_aliases_are_not_merged(self):
        source = self.frame(["2025-03-06 13:15:10.797"]*3)
        source["User"] = [" \t ", "root(uid=0)", "root"]
        source["Decoder_name"] = [None, "NA", ""]
        result = normalize_logs(source)
        self.assertTrue(pd.isna(result.User.iloc[0]))
        self.assertEqual(result.User.iloc[1:].tolist(), ["root(uid=0)", "root"])
        self.assertEqual(result.Decoder_name.iloc[1], "na")
        self.assertTrue(pd.isna(result.Decoder_name.iloc[0]))

    def test_raw_log_and_extra_columns_and_input_attrs_unchanged(self):
        source = self.frame()
        raw = ' \t"Mixed CASE", NA\r\nlogin failed\n '
        source["Full_log"] = raw
        source["Description"] = " NA "
        source["Content"] = ""
        source["custom"] = " Do NOT Strip "
        source["Anomaly"] = "1"
        source.attrs["load_report"] = {"file_sha256": DIGEST, "notes": ["original"]}
        baseline = source.copy(deep=True)
        attrs = copy.deepcopy(source.attrs)
        result = normalize_logs(source)
        for column in ["Full_log", "Description", "Content", "custom", "Anomaly"]:
            self.assertEqual(result.at[0, column], source.at[0, column])
        result.attrs["load_report"]["notes"].append("result only")
        pd.testing.assert_frame_equal(source, baseline)
        self.assertEqual(source.attrs, attrs)

    def test_anomaly_is_optional_and_does_not_affect_normalization(self):
        source = self.frame()
        expected = normalize_logs(source)
        for value in ["0", "1", "arbitrary"]:
            source["Anomaly"] = value
            actual = normalize_logs(source).drop(columns="Anomaly")
            pd.testing.assert_frame_equal(actual, expected)
            self.assertEqual(actual.attrs, expected.attrs)

    def test_create_keys_before_sort_from_explicit_file_hash(self):
        source = self.frame(["2025-03-07 00:00:00.000", "2025-03-06 00:00:00.000"]).drop(columns=["source_row_id", "record_index"])
        result = normalize_logs(source, file_sha256=DIGEST)
        self.assertEqual(result.record_index.tolist(), [1, 0])
        self.assertEqual(result.source_row_id.tolist(), [DIGEST+":00000001", DIGEST+":00000000"])
        self.assertNotIn("record_index", source)

    def test_keys_created_from_loader_hash_without_reindexing_filtered_data(self):
        source = self.frame().drop(columns="source_row_id")
        source["record_index"] = [99]
        source.attrs["load_report"] = {"file_sha256": DIGEST}
        result = normalize_logs(source)
        self.assertEqual(result.source_row_id.iloc[0], DIGEST+":00000099")

    def test_no_invented_hash_or_repaired_duplicate_keys(self):
        source = self.frame().drop(columns="source_row_id")
        with self.assertRaisesRegex(ValueError, "file_sha256"):
            normalize_logs(source)
        source = self.frame(["2025-03-06 13:15:10.797"]*2)
        for invalid_ids in [["same", "same"], ["good", ""], ["good", None], ["good", 3]]:
            source["source_row_id"] = invalid_ids
            with self.subTest(ids=invalid_ids), self.assertRaisesRegex(ValueError, "source_row_id"):
                normalize_logs(source)

    def test_invalid_record_indices_rejected(self):
        source = self.frame()
        for values in [[-1], [1.2], [None], [True], ["1"]]:
            source["record_index"] = values
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "record_index"):
                normalize_logs(source)

    def test_schema_missing_columns_and_reserved_names_rejected(self):
        with self.assertRaisesRegex(ValueError, "Activity"):
            normalize_logs(self.frame().drop(columns="Activity"))
        source = self.frame()
        source["Timestamp_raw"] = "do not overwrite"
        with self.assertRaisesRegex(ValueError, "reserved"):
            normalize_logs(source)
        source = self.frame()
        source.columns = ["id"]*len(source.columns)
        with self.assertRaisesRegex(ValueError, "(?i)duplicate"):
            normalize_logs(source)
        with self.assertRaises(TypeError):
            normalize_logs([])

    def test_schema_optional_fields_and_empty_frame(self):
        source = self.frame().drop(columns="Decoder_name")
        result = normalize_logs(source)
        self.assertEqual(result.columns[:len(EVENT_COLUMNS)].tolist(), list(EVENT_COLUMNS))
        for column in ["Decoder_name", "Full_log", "Description", "Content"]:
            self.assertTrue(pd.isna(result.at[0, column]))
        empty = normalize_logs(source.iloc[:0])
        self.assertEqual(len(empty), 0)
        self.assertEqual(str(empty.Timestamp.dtype), "datetime64[ns]")

    def test_idempotent_on_valid_and_invalid_timestamps(self):
        first = normalize_logs(self.frame(["bad", "2025-03-06 13:15:10.797"]))
        second = normalize_logs(first)
        pd.testing.assert_frame_equal(first, second)
        self.assertEqual(first.attrs, second.attrs)
        self.assertFalse(any(c.endswith("_raw_raw") for c in second.columns))
        for column in SOURCE_COLUMNS:
            self.assertIn(column+"_raw", second)

    def test_loader_integration_preserves_existing_ids_numeric_flags_and_raw(self):
        content = io.StringIO(newline="")
        columns = ["id", "Timestamp", "User", "Agent_name", "Activity", "Action", "Size_before", "Full_log"]
        writer = csv.DictWriter(content, fieldnames=columns)
        writer.writeheader()
        writer.writerow({"id": "a", "Timestamp": "bad", "User": "", "Agent_name": " HOST ", "Activity": " FILE ", "Action": " File Modified ", "Size_before": "-5.0", "Full_log": " RAW\nMixed "})
        loaded = load_logs(io.BytesIO(content.getvalue().encode()))
        result = normalize_logs(loaded)
        self.assertEqual(result.source_row_id.tolist(), loaded.source_row_id.tolist())
        self.assertEqual(result.Size_before.iloc[0], -5)
        self.assertEqual(result.Size_before_raw.iloc[0], "-5.0")
        self.assertTrue(result.has_numeric_issue.iloc[0])
        self.assertTrue(result.invalid_timestamp.iloc[0])
        self.assertEqual(result.Full_log.iloc[0], " RAW\nMixed ")
        self.assertEqual(result.attrs["load_report"], loaded.attrs["load_report"])


if __name__ == "__main__":
    unittest.main()
