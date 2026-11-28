"""Loader validation, raw preservation and upload compatibility."""
import csv
import hashlib
import io
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from preprocessing.log_loader import LogEncodingError, LogLoadError, load_logs


class LogLoaderTests(unittest.TestCase):
    columns = ["id", "Timestamp", "Agent_name", "User", "Activity", "Action"]

    def record(self, **changes):
        return {"id": "event-1", "Timestamp": "2025-03-06 11:46:28.000", "Agent_name": "host",
                "User": "irene", "Activity": "session", "Action": "Login", **changes}

    def payload(self, records=None, columns=None, encoding="utf-8-sig"):
        columns = columns or self.columns
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records if records is not None else [self.record()])
        return stream.getvalue().encode(encoding)

    def test_correct_path_and_duplicate_ids_kept(self):
        data = self.payload([self.record(), self.record()])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "logs.csv"
            path.write_bytes(data)
            frame = load_logs(path)
            self.assertEqual(path.read_bytes(), data)
        report = frame.attrs["load_report"]
        self.assertEqual((report["rows_read"], report["rows_loaded"], report["rows_skipped"]), (2, 2, 0))
        self.assertEqual(report["missing_columns"], [])
        self.assertEqual(report["duplicate_id_rows"], 1)
        self.assertEqual(frame.record_index.tolist(), [0, 1])
        self.assertEqual(frame.source_row_id.nunique(), 2)
        self.assertEqual(frame.source_row_id.iloc[0], hashlib.sha256(data).hexdigest()+":00000000")

    def test_upload_cursor_and_source_ids_match_path(self):
        upload = io.BytesIO(self.payload())
        upload.seek(8)
        first = load_logs(upload)
        second = load_logs(upload)
        self.assertEqual(upload.tell(), 8)
        self.assertFalse(upload.closed)
        pd.testing.assert_frame_equal(first, second)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "renamed.csv"
            path.write_bytes(upload.getvalue())
            pd.testing.assert_frame_equal(first, load_logs(str(path)))

    def test_binary_file_stream_position_restored(self):
        with tempfile.TemporaryFile(mode="w+b") as stream:
            stream.write(self.payload())
            stream.seek(5)
            self.assertEqual(len(load_logs(stream)), 1)
            self.assertEqual(stream.tell(), 5)
            self.assertFalse(stream.closed)

    def test_missing_columns_lists_exact_names_on_exception(self):
        with self.assertRaises(LogLoadError) as context:
            load_logs(io.BytesIO(b"id,User\na,b\n"))
        self.assertEqual(context.exception.report["missing_columns"], ["Action", "Activity", "Agent_name", "Timestamp"])
        for name in context.exception.report["missing_columns"]:
            self.assertIn(name, str(context.exception))

    def test_empty_files_and_header_only(self):
        for data in (b"", b"\xef\xbb\xbf", b" \r\n\t", self.payload([])):
            with self.subTest(data=data), self.assertRaises(LogLoadError) as context:
                load_logs(io.BytesIO(data))
            self.assertEqual(context.exception.report["status"], "error")
            self.assertEqual(context.exception.report["rows_loaded"], 0)

    def test_field_count_error_default_and_explicit_skip_with_index_gap(self):
        base = self.payload(encoding="utf-8").decode()
        data = (base+"broken,short\n"+base.splitlines()[1]+"\n").encode()
        with self.assertRaisesRegex(LogLoadError, "Incorrect field count"):
            load_logs(io.BytesIO(data))
        frame = load_logs(io.BytesIO(data), on_bad_lines="skip")
        self.assertEqual(frame.record_index.tolist(), [0, 2])
        report = frame.attrs["load_report"]
        self.assertEqual((report["rows_read"], report["rows_loaded"], report["rows_skipped"]), (3, 2, 1))
        self.assertEqual(report["skipped_records"][0]["record_index"], 1)
        self.assertEqual(report["skipped_records"][0]["physical_line_start"], 3)

    def test_extra_fields_are_not_used_as_index(self):
        data = self.payload(encoding="utf-8").decode().rstrip()+",extra\n"
        with self.assertRaisesRegex(LogLoadError, "Incorrect field count"):
            load_logs(io.BytesIO(data.encode()))

    def test_broken_quote_cannot_be_skipped_safely(self):
        data = self.payload(encoding="utf-8")+b'"unterminated\n'
        for policy in ("error", "skip"):
            with self.subTest(policy=policy), self.assertRaisesRegex(LogLoadError, "boundaries") as context:
                load_logs(io.BytesIO(data), on_bad_lines=policy)
            self.assertIn("unrecoverable_record", context.exception.report)

    def test_empty_required_value_but_nullable_user(self):
        frame = load_logs(io.BytesIO(self.payload([self.record(User=" \t"), self.record(User="NA")])))
        self.assertTrue(pd.isna(frame.User.iloc[0]))
        self.assertEqual(frame.User.iloc[1], "NA")
        for column in ("id", "Timestamp", "Agent_name", "Activity", "Action"):
            with self.subTest(column=column), self.assertRaisesRegex(LogLoadError, column):
                load_logs(io.BytesIO(self.payload([self.record(**{column: " "})])))

    def test_empty_required_record_can_be_skipped_explicitly(self):
        data = self.payload([self.record(id=""), self.record(id="ok")])
        frame = load_logs(io.BytesIO(data), on_bad_lines="skip")
        self.assertEqual(frame.id.tolist(), ["ok"])
        self.assertEqual(frame.record_index.tolist(), [1])
        self.assertEqual(frame.attrs["load_report"]["rows_skipped"], 1)

    def test_multiline_raw_and_additional_column_preserved(self):
        raw = ' \tNA, "login failed"\r\nsecond line\n '
        columns = self.columns+["Full_log", "Description", "Content", "extra"]
        record = self.record(Full_log=raw, Description=" NA ", Content="", extra="unknown")
        frame = load_logs(io.BytesIO(self.payload([record], columns)))
        for column in ("Full_log", "Description", "Content", "extra"):
            self.assertEqual(frame.at[0, column], record[column])
        self.assertEqual(frame.record_index.tolist(), [0])
        self.assertEqual(frame.Timestamp.iloc[0], record["Timestamp"])

    def test_missing_raw_columns_nullable_and_label_optional(self):
        frame = load_logs(io.BytesIO(self.payload()))
        self.assertNotIn("Anomaly", frame)
        for column in ("Full_log", "Description", "Content"):
            self.assertTrue(pd.isna(frame.at[0, column]))

    def test_numeric_nullable_raw_invalid_nonfinite_negative(self):
        columns = self.columns+["Size_before", "Size", "Anomaly"]
        records = [self.record(Size_before="-5.0", Size="", Anomaly="1"),
                   self.record(Size_before="abc", Size="inf", Anomaly="0"),
                   self.record(Size_before="2.0", Size="NaN", Anomaly="not-evaluated")]
        frame = load_logs(io.BytesIO(self.payload(records, columns)))
        self.assertEqual(str(frame.Size_before.dtype), "Float64")
        self.assertEqual(frame.Size_before.iloc[0], -5)
        self.assertTrue(pd.isna(frame.Size_before.iloc[1]))
        self.assertTrue(frame.Size.isna().all())
        self.assertEqual(frame.Size_before_raw.tolist(), ["-5.0", "abc", "2.0"])
        self.assertEqual(len(frame.attrs["load_report"]["numeric_issues"]), 4)
        self.assertTrue(frame.has_numeric_issue.all())
        self.assertEqual(frame.Anomaly.tolist(), ["1", "0", "not-evaluated"])

    def test_utf8_and_bom_and_explicit_encoding(self):
        for encoding in ("utf-8", "utf-8-sig"):
            frame = load_logs(io.BytesIO(self.payload([self.record(User="User \U0001f600")], encoding=encoding)))
            self.assertEqual(frame.User.iloc[0], "User \U0001f600")
        data = self.payload([self.record(User="café")], encoding="cp1252")
        with self.assertRaises(LogEncodingError) as context:
            load_logs(io.BytesIO(data))
        self.assertEqual(context.exception.report["status"], "error")
        self.assertEqual(load_logs(io.BytesIO(data), encoding="cp1252").User.iloc[0], "café")

    def test_duplicate_empty_or_reserved_headers(self):
        for suffix in (",id", ",", ",source_row_id", ",Size_raw"):
            data = (",".join(self.columns)+suffix+"\n").encode()
            with self.subTest(suffix=suffix), self.assertRaises(LogLoadError):
                load_logs(io.BytesIO(data))

    def test_all_skipped_is_error_with_report(self):
        data = ",".join(self.columns).encode()+b"\nbad\n"
        with self.assertRaises(LogLoadError) as context:
            load_logs(io.BytesIO(data), on_bad_lines="skip")
        self.assertEqual(context.exception.report["rows_skipped"], 1)
        self.assertEqual(context.exception.report["rows_read"], 1)

    def test_blank_lines_ignored_without_changing_logical_index(self):
        data = self.payload(encoding="utf-8").decode()
        data += "\n"+data.splitlines()[1]+"\n"
        frame = load_logs(io.BytesIO(data.encode()))
        self.assertEqual(frame.record_index.tolist(), [0, 1])
        self.assertEqual(frame.attrs["load_report"]["blank_lines_ignored"], 1)

    def test_invalid_source_policy_nul_and_missing_file(self):
        with self.assertRaises(TypeError):
            load_logs(io.StringIO("text"))
        with self.assertRaises(ValueError):
            load_logs(io.BytesIO(self.payload()), on_bad_lines="ignore")
        with self.assertRaises(LogLoadError):
            load_logs(io.BytesIO(b"id\x00,User\n"))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                load_logs(Path(folder)/"absent.csv")


if __name__ == "__main__":
    unittest.main()
