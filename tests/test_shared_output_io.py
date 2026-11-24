"""Task 4-6 artifact round-trip, strict schema, JSON cells and references."""
import copy
from pathlib import Path
import tempfile
import unittest

import pandas as pd

from detection.alert_aggregation import merge_alerts
from detection.correlation import correlate, get_timeline
from detection.rule_engine import detect_rules
from detection.shared_output_io import (
    save_atomic_alerts, read_atomic_alerts, save_alerts, read_alerts,
    save_event_groups, read_event_groups,
)


class SharedOutputIOTests(unittest.TestCase):
    def events(self):
        frame = pd.DataFrame({
            "Timestamp": pd.to_datetime(["2025-03-06 12:00:00.123", "2025-03-06 12:00:01.123", "2025-03-06 12:00:02.123"]).astype("datetime64[ns]"),
            "User": ["__SPEDIA_NULL__", None, "bob"], "Agent_name": ["host"]*3,
            "Activity": ["command"]*3, "Action": ["command executed"]*3,
            "source_row_id": ["a"*64+f":{i:08d}" for i in range(3)], "record_index": [0, 1, 2],
            "Command": ["nmap"]*3, "Full_log": [' Raw "quoted", NA\r\nline\n ']*3,
            "Description": ["", "NA", "null"], "Content": ["", "", ""],
        })
        return frame

    def atomic(self):
        return detect_rules(self.events(), config={"enabled_rule_ids": ["CMD_NMAP"]})

    def test_atomic_round_trip_raw_json_literal_null_marker_and_none_user(self):
        alerts = self.atomic()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"atomic.csv"
            meta = save_atomic_alerts(alerts, path)
            self.assertNotEqual(meta["null_marker"], "__SPEDIA_NULL__")
            self.assertEqual(read_atomic_alerts(path), alerts)
            self.assertIsNone(read_atomic_alerts(path)[1]["user"])

    def test_merged_v1_round_trip_has_lists_no_extra_root_rule_id(self):
        merged = merge_alerts(self.atomic())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"alerts.csv"
            save_alerts(merged, path, provenance={"source_sha256": "a"*64})
            restored = read_alerts(path)
            self.assertEqual(restored, merged)
            self.assertIsInstance(restored[0]["rule_ids"], list)
            self.assertIsInstance(restored[0]["rule_matches"][0]["evidence"], dict)
            self.assertNotIn("rule_id", restored[0])

    def test_group_round_trip_counts_key_lists_dates_attrs_and_timeline(self):
        events, merged = self.events(), merge_alerts(self.atomic())
        groups = correlate(events, merged)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"groups.csv"
            save_event_groups(groups, path)
            restored = read_event_groups(path)
            pd.testing.assert_frame_equal(restored, groups, check_exact=True)
            self.assertEqual(restored.attrs, groups.attrs)
            self.assertEqual(restored.key.iloc[0], {"user": "__SPEDIA_NULL__", "agent": "host"})
            gid = restored.group_id.iloc[0]
            pd.testing.assert_frame_equal(get_timeline(events, gid, merged), get_timeline(events, gid, read_alerts(self._save_merged(folder, merged))))

    def _save_merged(self, folder, merged):
        path = Path(folder)/"merged.csv"
        save_alerts(merged, path)
        return path

    def test_not_run_nullable_counts_survive_group_csv(self):
        groups = correlate(self.events(), None)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"groups.csv"
            save_event_groups(groups, path)
            restored = read_event_groups(path)
            self.assertTrue(restored.alert_count.isna().all())
            self.assertEqual(restored.attrs["correlation_report"]["detector_state"], "not_run")
            pd.testing.assert_frame_equal(restored, groups, check_exact=True)

    def test_empty_artifacts_have_stable_headers(self):
        with tempfile.TemporaryDirectory() as folder:
            atomic, merged, groups = (Path(folder)/name for name in ("atomic.csv", "merged.csv", "groups.csv"))
            save_atomic_alerts([], atomic)
            save_alerts([], merged)
            self.assertEqual(read_atomic_alerts(atomic), [])
            self.assertEqual(read_alerts(merged), [])
            empty = correlate(self.events().iloc[:0], [])
            save_event_groups(empty, groups)
            pd.testing.assert_frame_equal(read_event_groups(groups), empty, check_exact=True)

    def test_missing_sidecar_tamper_or_wrong_reader_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"alerts.csv"
            with self.assertRaises(FileNotFoundError):
                read_alerts(path)
            save_alerts(merge_alerts(self.atomic()), path)
            with self.assertRaises(ValueError):
                read_atomic_alerts(path)
            with path.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "Checksum"):
                read_alerts(path)

    def test_duplicate_or_conflicting_alerts_rejected_before_export(self):
        atomic = self.atomic()
        merged = merge_alerts(atomic)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "(?i)duplicate"):
                save_atomic_alerts(atomic+atomic[:1], Path(folder)/"atomic.csv")
            with self.assertRaisesRegex(ValueError, "unique"):
                save_alerts(merged+merged[:1], Path(folder)/"merged.csv")

    def test_groups_bad_count_or_reused_source_or_key_rejected(self):
        groups = correlate(self.events(), merge_alerts(self.atomic()))
        with tempfile.TemporaryDirectory() as folder:
            for change in ("count", "source", "key"):
                bad = copy.deepcopy(groups)
                if change == "count": bad.loc[0, "event_count"] = 999
                elif change == "source": bad.at[1, "source_row_ids"] = bad.at[0, "source_row_ids"]
                else: bad.at[0, "key"] = {"user": "wrong", "agent": "host"}
                with self.subTest(change=change), self.assertRaises(ValueError):
                    save_event_groups(bad, Path(folder)/(change+".csv"))

    def test_unowned_target_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"source.csv"
            path.write_text("original source", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                save_alerts(merge_alerts(self.atomic()), path)
            self.assertEqual(path.read_text(encoding="utf-8"), "original source")

    def test_input_alerts_groups_and_metadata_not_modified(self):
        atomic = self.atomic()
        merged = merge_alerts(atomic)
        groups = correlate(self.events(), merged)
        saved_atomic, saved_merged, saved_groups = copy.deepcopy(atomic), copy.deepcopy(merged), groups.copy(deep=True)
        origin = {"source": ["original"]}
        with tempfile.TemporaryDirectory() as folder:
            save_atomic_alerts(atomic, Path(folder)/"atomic.csv", provenance=origin)
            save_alerts(merged, Path(folder)/"merged.csv", provenance=origin)
            save_event_groups(groups, Path(folder)/"groups.csv", provenance=origin)
        self.assertEqual(atomic, saved_atomic)
        self.assertEqual(merged, saved_merged)
        pd.testing.assert_frame_equal(groups, saved_groups)
        self.assertEqual(origin, {"source": ["original"]})


if __name__ == "__main__":
    unittest.main()
