from __future__ import annotations

from collections import Counter
from io import BytesIO
import hashlib
from pathlib import Path
import sys
import unittest

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from detection.correlation import correlate
from detection.pipeline import run_detection_pipeline
from detection.rule_engine import alerts_to_dataframe, detect_rules
from detection.severity import assign_severity
from preprocessing.data_bundle import load_table
from preprocessing.log_loader import LogLoadError, load_logs
from preprocessing.log_normalizer import normalize_logs
from preprocessing.source_ids import validate_source_row_ids


TEST_FILE_HASH = hashlib.sha256(b"analysis-pipeline-test-input").hexdigest()


def canonical_source_id(record_index):
    return f"{TEST_FILE_HASH}:{record_index:08d}"


class LogIngestionTest(unittest.TestCase):
    def test_loader_creates_repeatable_source_ids_and_validates_schema(self):
        csv_bytes = (
            b"id,Timestamp,Agent_name,User,Activity,Action,Decoder_name\n"
            b"1,2025-01-01 10:00:00.000,host-a,Alice,http,URL accessed,web\n"
        )
        first = load_logs(BytesIO(csv_bytes))
        second = load_logs(BytesIO(csv_bytes))
        self.assertEqual(first["source_row_id"].tolist(), second["source_row_id"].tolist())
        self.assertTrue(first["source_row_id"].iloc[0].endswith(":00000000"))
        with self.assertRaisesRegex(LogLoadError, "Missing required columns"):
            load_logs(BytesIO(b"Timestamp,User\n2025-01-01 10:00:00.000,Alice\n"))

    def test_source_id_validation_rejects_blank_and_duplicate(self):
        for ids in [
            [None, "source-2"],
            [" ", "source-2"],
            ["duplicate", "duplicate"],
        ]:
            frame = pd.DataFrame({"source_row_id": ids})
            with self.subTest(ids=ids), self.assertRaisesRegex(ValueError, "source_row_id"):
                validate_source_row_ids(frame, component="test")

    def test_normalizer_preserves_raw_fields_and_marks_bad_timestamps(self):
        frame = pd.DataFrame(
            [
                {
                    "id": "bad-time",
                    "Timestamp": "bad-time",
                    "User": " Alice ",
                    "Agent_name": " Host-A ",
                    "Activity": " HTTP ",
                    "Action": " URL ACCESSED ",
                    "Decoder_name": " Web ",
                    "source_row_id": "loader:00000000",
                },
                {
                    "id": "good-time",
                    "Timestamp": "2025-01-02 10:00:00.000",
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
        row = normalized.loc[normalized.source_row_id.eq("loader:00000000")].iloc[0]
        self.assertEqual(row["Activity"], "http")
        self.assertEqual(row["Action_raw"], " URL ACCESSED ")
        self.assertEqual(row["User_raw"], " Alice ")
        self.assertEqual(
            normalized["source_row_id"].tolist(),
            ["loader:00000001", "loader:00000000"],
        )
        self.assertTrue(row["invalid_timestamp"])
        self.assertTrue(pd.isna(row["Timestamp"]))
        self.assertTrue(normalized["source_row_id"].is_unique)

    def test_normalizer_requires_source_ids_from_loader(self):
        frame = pd.DataFrame(
            {
                "id": [1],
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
                "id": [1, 2],
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
                    "id": index,
                        "source_row_id": f"rule-event-{index}",
                    "Timestamp": f"2025-03-01 09:00:0{index}.000",
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
        alerts = alerts_to_dataframe(detect_rules(self.events))
        self.assertEqual(
            Counter(alerts["rule_id"].tolist()),
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
        self.assertNotIn("FILE_CONFIG_CHANGE", [alert["rule_id"] for alert in detect_rules(events)])

    def test_invalid_timestamp_rows_are_not_rule_alerted(self):
        events = self.events.iloc[[0]].copy()
        events["Timestamp"] = pd.NaT
        self.assertEqual(detect_rules(events), [])

    def test_rule_engine_rejects_blank_source_ids(self):
        events = self.events.copy()
        events.loc[events.index[0], "source_row_id"] = " "
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            detect_rules(events)

    def test_rules_match_the_validated_bundle_snapshot(self):
        events = load_table("normalized_logs.csv")
        expected = load_table("alerts_atomic.csv")
        actual = alerts_to_dataframe(detect_rules(events))
        expected_pairs = set(zip(expected["source_row_id"], expected["rule_id"]))
        actual_pairs = set(zip(actual["source_row_id"], actual["rule_id"]))
        self.assertEqual(actual_pairs, expected_pairs)


class CorrelationAndSeverityTest(unittest.TestCase):
    def test_correlation_respects_fixed_window_gap_and_missing_identity(self):
        events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "id": index,
                        "source_row_id": f"correlation-event-{index}",
                        "Timestamp": timestamp,
                        "User": user,
                        "Agent_name": "host-a",
                        "Activity": "file",
                        "Action": "file modified",
                        "Decoder_name": "test",
                    }
                    for index, (timestamp, user) in enumerate([
                        ("2025-03-01 09:14:59.000", "alice"),
                        ("2025-03-01 09:15:00.000", "alice"),
                        ("2025-03-01 09:20:01.000", "alice"),
                        ("2025-03-01 09:16:00.000", None),
                    ])
                ]
            )
        )
        groups = correlate(events, alerts=[])
        self.assertEqual(len(groups), 3)
        self.assertEqual(sum(len(ids) for ids in groups["source_row_ids"]), 3)

    def test_correlation_rejects_blank_source_ids(self):
        events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "id": 1,
                        "source_row_id": "correlation-event-1",
                        "Timestamp": "2025-03-01 09:00:00.000",
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
            correlate(events, alerts=[])

    def test_correlation_matches_validated_bundle_snapshot(self):
        events = load_table("normalized_logs.csv")
        actual = correlate(events, alerts=[])
        expected = load_table("event_groups.csv")
        actual_memberships = {frozenset(ids) for ids in actual["source_row_ids"]}
        expected_memberships = {frozenset(ids) for ids in expected["source_row_ids"]}
        self.assertEqual(actual_memberships, expected_memberships)

    def test_severity_is_rule_only_and_ml_argument_does_not_change_priority(self):
        events = normalize_logs(
            pd.DataFrame(
                [
                    {
                        "id": index,
                        "source_row_id": canonical_source_id(index),
                        "Timestamp": f"2025-03-01 10:{index:02d}:00.000",
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
                    }
                    for index in range(10)
                ]
            )
        )
        atomic = detect_rules(events)
        without_ml = assign_severity(atomic, events=events)
        with_ml = assign_severity(atomic, ml_results=object(), events=events)
        self.assertEqual(with_ml, without_ml)
        priority = {alert["source_row_id"]: alert["severity"] for alert in without_ml}
        self.assertEqual(priority[canonical_source_id(0)], "MEDIUM")
        self.assertEqual(priority[canonical_source_id(1)], "MEDIUM")
        self.assertEqual(priority[canonical_source_id(9)], "CRITICAL")

    def test_severity_rejects_blank_source_ids(self):
        events = normalize_logs(pd.DataFrame([{
            "id": 1,
            "source_row_id": canonical_source_id(0),
            "Timestamp": "2025-03-01 10:00:00.000",
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
        }]))
        alerts = detect_rules(events)
        events.loc[events.index[0], "source_row_id"] = " "
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            assign_severity(alerts, events=events)


class AnalysisPipelineTest(unittest.TestCase):
    def test_pipeline_preserves_ids_and_runs_rule_correlation_and_severity(self):
        events = normalize_logs(pd.DataFrame(
            [
                {
                    "id": 1,
                    "source_row_id": canonical_source_id(0),
                    "Timestamp": "2025-03-01 09:00:00.000",
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
                    "id": 2,
                    "source_row_id": canonical_source_id(1),
                    "Timestamp": "2025-03-01 09:01:00.000",
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
        ))

        result = run_detection_pipeline(events)

        expected_ids = [canonical_source_id(0), canonical_source_id(1)]
        self.assertEqual(result["detected_logs"]["source_row_id"].tolist(), expected_ids)
        self.assertEqual(
            {alert["rule_id"] for alert in result["atomic_alerts"]},
            {"CMD_NMAP", "HTTP_IP_HOST"},
        )
        self.assertTrue(
            all(alert["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for alert in result["alerts"])
        )
        self.assertEqual(result["report"]["rows_input"], 2)
        self.assertFalse(result["report"]["ML_used"])


if __name__ == "__main__":
    unittest.main()
