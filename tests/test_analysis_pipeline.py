from __future__ import annotations

from pathlib import Path
import sys
import unittest

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from detection.correlation import correlate_events
from detection.pipeline import analyze_events
from detection.rule_engine import run_rules
from detection.severity import assign_severity
from preprocessing.data_bundle import load_table
from preprocessing.log_loader import load_log_csv
from preprocessing.log_normalizer import normalize_logs


class LogIngestionTest(unittest.TestCase):
    def test_loader_creates_repeatable_source_ids_and_validates_schema(self):
        csv_bytes = (
            b"Timestamp,User,Agent_name,Activity,Action,Decoder_name\n"
            b"2025-01-01 10:00:00,Alice,host-a,http,URL accessed,web\n"
        )
        first = load_log_csv(csv_bytes)
        second = load_log_csv(csv_bytes)
        self.assertEqual(first["source_row_id"].tolist(), second["source_row_id"].tolist())
        self.assertTrue(first["source_row_id"].iloc[0].endswith(":00000000"))
        with self.assertRaisesRegex(ValueError, "Thiếu cột bắt buộc"):
            load_log_csv(b"Timestamp,User\n2025-01-01 10:00:00,Alice\n")

    def test_loader_rejects_blank_and_duplicate_source_ids(self):
        header = (
            b"Timestamp,User,Agent_name,Activity,Action,Decoder_name,source_row_id\n"
        )
        for rows in [
            b"2025-01-01 10:00:00,Alice,host-a,http,URL accessed,web, \n",
            (
                b"2025-01-01 10:00:00,Alice,host-a,http,URL accessed,web,same\n"
                b"2025-01-01 10:01:00,Alice,host-a,http,URL accessed,web,same\n"
            ),
        ]:
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(ValueError, "source_row_id"):
                    load_log_csv(header + rows)

    def test_normalizer_preserves_raw_fields_and_marks_bad_timestamps(self):
        frame = pd.DataFrame(
            [
                {
                    "Timestamp": "bad-time",
                    "User": " Alice ",
                    "Agent_name": " Host-A ",
                    "Activity": " HTTP ",
                    "Action": " URL ACCESSED ",
                    "Decoder_name": " Web ",
                    "source_row_id": "loader:00000000",
                },
                {
                    "Timestamp": "2025-01-02 10:00:00",
                    "User": "Bob",
                    "Agent_name": "host-b",
                    "Activity": "file",
                    "Action": "file modified",
                    "Decoder_name": "file",
                    "source_row_id": "loader:00000001",
                },
            ]
        )
        normalized = normalize_logs(frame)
        row = normalized.iloc[0]
        self.assertEqual(row["Activity"], "http")
        self.assertEqual(row["Action_raw"], " URL ACCESSED ")
        self.assertEqual(row["User_raw"], " Alice ")
        self.assertEqual(
            normalized["source_row_id"].tolist(),
            ["loader:00000000", "loader:00000001"],
        )
        self.assertTrue(row["invalid_timestamp"])
        self.assertTrue(pd.isna(row["Timestamp"]))
        self.assertTrue(normalized["source_row_id"].is_unique)

    def test_normalizer_requires_source_ids_from_loader(self):
        frame = pd.DataFrame(
            {
                "Timestamp": ["2025-01-01 10:00:00"],
                "User": ["alice"],
                "Agent_name": ["host-a"],
                "Activity": ["http"],
                "Action": ["URL accessed"],
                "Decoder_name": ["web"],
            }
        )
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            normalize_logs(frame)

    def test_normalizer_rejects_blank_or_duplicate_source_ids(self):
        frame = pd.DataFrame(
            {
                "Timestamp": ["2025-01-01 10:00:00", "2025-01-01 10:01:00"],
                "User": ["alice", "alice"],
                "Agent_name": ["host-a", "host-a"],
                "Activity": ["http", "http"],
                "Action": ["URL accessed", "URL accessed"],
                "Decoder_name": ["web", "web"],
                "source_row_id": ["same", "same"],
            }
        )
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            normalize_logs(frame)


class RuleEngineTest(unittest.TestCase):
    def setUp(self):
        self.events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "source_row_id": f"rule-event-{index}",
                        "Timestamp": f"2025-03-01 09:00:0{index}",
                        "User": "alice",
                        "Agent_name": "host-a",
                        "Activity": activity,
                        "Action": action,
                        "Decoder_name": "test",
                        "Command": command,
                        "Path": path,
                        "Full_log": full_log,
                        "Description": description,
                        "Url": url,
                    }
                    for index, activity, action, command, path, full_log, description, url in [
                        (0, "command", "command executed", "/usr/bin/nmap", "", "", "", ""),
                        (1, "file", "file modified", "", "/etc/ssh/sshd_config", "Changed attributes: mtime,md5 Old modification time", "Integrity checksum changed.", ""),
                        (2, "http", "url accessed", "", "", "", "", "http://192.0.2.1/path"),
                        (3, "session", "login failed", "", "", "authentication failure", "", ""),
                        (4, "session", "login failed", "", "", "authentication failure", "", ""),
                        (5, "session", "login failed", "", "", "authentication failure", "", ""),
                    ]
                ]
            )
        )

    def test_enabled_rules_emit_traceable_alerts(self):
        alerts = run_rules(self.events)
        self.assertEqual(
            alerts["rule_id"].value_counts().to_dict(),
            {
                "AUTH_FAILURE_WINDOW": 1,
                "CMD_NMAP": 1,
                "FILE_CONFIG_CHANGE": 1,
                "HTTP_IP_HOST": 1,
            },
        )
        self.assertTrue(alerts["reason"].str.len().gt(0).all())
        self.assertTrue(alerts["source_row_id"].isin(self.events["source_row_id"]).all())

    def test_modified_file_with_only_mtime_change_is_not_alerted(self):
        events = self.events.iloc[[1]].copy()
        events["Full_log"] = "Changed attributes: mtime,ctime Old modification time"
        self.assertNotIn("FILE_CONFIG_CHANGE", run_rules(events)["rule_id"].tolist())

    def test_invalid_timestamp_rows_are_not_rule_alerted(self):
        events = self.events.iloc[[0]].copy()
        events["Timestamp"] = pd.NaT
        self.assertTrue(run_rules(events).empty)

    def test_rule_engine_rejects_blank_source_ids(self):
        events = self.events.copy()
        events.loc[events.index[0], "source_row_id"] = " "
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            run_rules(events)

    def test_rules_match_the_validated_bundle_snapshot(self):
        events = load_table("normalized_logs.csv")
        expected = load_table("alerts_atomic.csv")
        actual = run_rules(events)
        expected_pairs = set(zip(expected["source_row_id"], expected["rule_id"]))
        actual_pairs = set(zip(actual["source_row_id"], actual["rule_id"]))
        self.assertEqual(actual_pairs, expected_pairs)


class CorrelationAndSeverityTest(unittest.TestCase):
    def test_correlation_respects_fixed_window_gap_and_missing_identity(self):
        events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "source_row_id": f"correlation-event-{index}",
                        "Timestamp": timestamp,
                        "User": user,
                        "Agent_name": "host-a",
                        "Activity": "file",
                        "Action": "file modified",
                        "Decoder_name": "test",
                    }
                    for index, (timestamp, user) in enumerate([
                        ("2025-03-01 09:14:59", "alice"),
                        ("2025-03-01 09:15:00", "alice"),
                        ("2025-03-01 09:20:01", "alice"),
                        ("2025-03-01 09:16:00", None),
                    ])
                ]
            )
        )
        correlated, groups = correlate_events(events)
        self.assertEqual(len(groups), 3)
        self.assertEqual(correlated["group_id"].isna().sum(), 1)

    def test_correlation_rejects_blank_source_ids(self):
        events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "source_row_id": "correlation-event-1",
                        "Timestamp": "2025-03-01 09:00:00",
                        "User": "alice",
                        "Agent_name": "host-a",
                        "Activity": "file",
                        "Action": "file modified",
                        "Decoder_name": "test",
                    }
                ]
            )
        )
        events.loc[events.index[0], "source_row_id"] = ""
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            correlate_events(events)

    def test_correlation_matches_validated_bundle_snapshot(self):
        events = load_table("normalized_logs.csv")
        _, actual = correlate_events(events)
        expected = load_table("event_groups.csv")
        actual_memberships = {frozenset(ids) for ids in actual["source_row_ids"]}
        expected_memberships = {frozenset(ids) for ids in expected["source_row_ids"]}
        self.assertEqual(actual_memberships, expected_memberships)

    def test_severity_uses_rule_and_ml_corroboration_without_future_events(self):
        timestamps = pd.date_range("2025-03-01 10:00:00", periods=10, freq="min")
        events = pd.DataFrame(
            {
                "source_row_id": [f"event-{index}" for index in range(10)],
                "Timestamp": timestamps,
                "Activity": ["command", "file", "http", "file"] * 2 + ["file", "file"],
                "group_id": "group-1",
                "record_index": range(10),
            }
        )
        alerts = pd.DataFrame(
            [
                {"source_row_id": "event-0", "rule_id": "CMD_NMAP", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-0", "rule_id": "ML_ANOMALY", "source": "ML", "anomaly_score": 0.9},
                {"source_row_id": "event-1", "rule_id": "CMD_NMAP", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-2", "rule_id": "HTTP_IP_HOST", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-3", "rule_id": "CMD_JOHN", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-4", "rule_id": "CMD_MSFCONSOLE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-5", "rule_id": "FILE_CONFIG_CHANGE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-6", "rule_id": "FILE_CONFIG_CHANGE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-7", "rule_id": "FILE_CONFIG_CHANGE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-8", "rule_id": "FILE_CONFIG_CHANGE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-9", "rule_id": "FILE_CONFIG_CHANGE", "source": "Rule Engine", "anomaly_score": pd.NA},
                {"source_row_id": "event-9", "rule_id": "ML_ANOMALY", "source": "ML", "anomaly_score": 0.95},
            ]
        )
        result = assign_severity(events, alerts)
        at_start = result[result["source_row_id"] == "event-0"]
        before_future_signals = result[result["source_row_id"] == "event-1"]
        at_end = result[result["source_row_id"] == "event-9"]
        self.assertEqual(set(at_start["severity"]), {"HIGH"})
        self.assertEqual(set(before_future_signals["severity"]), {"MEDIUM"})
        self.assertEqual(set(at_end["severity"]), {"CRITICAL"})
        self.assertTrue(result["severity_reason"].str.len().gt(0).all())

    def test_severity_rejects_blank_source_ids(self):
        events = pd.DataFrame(
            {
                "source_row_id": [" "],
                "Timestamp": [pd.Timestamp("2025-03-01 10:00:00")],
                "group_id": [pd.NA],
            }
        )
        alerts = pd.DataFrame(
            columns=["source_row_id", "rule_id", "source"]
        )
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            assign_severity(events, alerts)


class AnalysisPipelineTest(unittest.TestCase):
    def test_pipeline_preserves_ids_and_runs_ml_rules_correlation_and_severity(self):
        events = pd.DataFrame(
            [
                {
                    "source_row_id": "input-event-1",
                    "Timestamp": "2025-03-01 09:00:00",
                    "User": "alice",
                    "Agent_name": "host-a",
                    "Activity": "command",
                    "Action": "command executed",
                    "Decoder_name": "test",
                    "Command": "/usr/bin/nmap",
                    "Path": "",
                    "Full_log": "",
                    "Description": "",
                    "Url": "",
                },
                {
                    "source_row_id": "input-event-2",
                    "Timestamp": "2025-03-01 09:01:00",
                    "User": "alice",
                    "Agent_name": "host-a",
                    "Activity": "http",
                    "Action": "URL accessed",
                    "Decoder_name": "test",
                    "Command": "",
                    "Path": "",
                    "Full_log": "",
                    "Description": "",
                    "Url": "http://192.0.2.1/path",
                },
            ]
        )

        result = analyze_events(
            events,
            model_name="random_forest_behavioral.joblib",
            threshold=0.99,
        )

        expected_ids = ["input-event-1", "input-event-2"]
        self.assertEqual(result["events"]["source_row_id"].tolist(), expected_ids)
        self.assertEqual(result["predictions"]["source_row_id"].tolist(), expected_ids)
        self.assertEqual(
            set(result["rule_alerts"]["rule_id"]),
            {"CMD_NMAP", "HTTP_IP_HOST"},
        )
        self.assertTrue(result["alerts"]["severity"].isin(
            {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        ).all())
        self.assertEqual(result["diagnostics"]["input_rows"], 2)


if __name__ == "__main__":
    unittest.main()
