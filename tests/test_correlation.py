"""Grouping/timeline correctness, causal membership and historical snapshots."""
import copy
import unittest

import pandas as pd

from detection.correlation import GROUP_COLUMNS, correlate, correlate_events, get_timeline

CFG = {"window_seconds": 900, "max_gap_seconds": 300, "min_events": 1}


class CorrelationTests(unittest.TestCase):
    def events(self, rows=None):
        rows = [{}] if rows is None else rows
        base = [{"Timestamp": pd.Timestamp("2025-03-06 12:00:00")+pd.Timedelta(seconds=i*60),
                 "User": "alice", "Agent_name": "host-a", "Activity": "command",
                 "Action": "command executed", "record_index": i,
                 "source_row_id": "a"*64+f":{i:08d}", "Full_log": ' Raw "Mixed"\r\n ',
                 "Description": " NA ", "Content": "", **row} for i, row in enumerate(rows)]
        if not rows:
            return self.events().iloc[:0].copy()
        return pd.DataFrame(base)

    def pairs(self, events, indices, rule="RULE_A"):
        return [{"source_row_id": events.source_row_id.iloc[i], "rule_id": rule} for i in indices]

    def memberships(self, groups):
        return {sid: g["group_id"] for g in groups.to_dict("records") for sid in g["source_row_ids"]}

    def test_same_user_agent_group_fields_and_activity_order(self):
        events = self.events([{"Activity": "session"}, {}, {"Activity": "file"}, {}])
        groups = correlate(events, [], config=CFG)
        self.assertEqual(groups.columns.tolist(), list(GROUP_COLUMNS))
        self.assertEqual(len(groups), 1)
        group = groups.iloc[0]
        self.assertEqual(group.key, {"user": "alice", "agent": "host-a"})
        self.assertEqual(group.event_count, 4)
        self.assertEqual(group.activities, ["session", "command", "file"])
        self.assertEqual(group.source_row_ids, events.source_row_id.tolist())
        self.assertEqual((group.start_time, group.end_time), (events.Timestamp.iloc[0], events.Timestamp.iloc[-1]))

    def test_separate_users_and_agents(self):
        events = self.events([{}, {"User": "bob"}, {"Agent_name": "host-b"}])
        groups = correlate(events, [], config=CFG)
        self.assertEqual(len(groups), 3)
        self.assertEqual(groups.group_id.nunique(), 3)

    def test_gap_equal_threshold_same_group_exceed_threshold_split(self):
        origin = pd.Timestamp("2025-03-06 12:00:00")
        events = self.events([{"Timestamp": origin+pd.Timedelta(seconds=s)} for s in [0, 300, 601]])
        groups = correlate(events, [], config=CFG)
        self.assertEqual(groups.event_count.tolist(), [2, 1])

    def test_fixed_window_boundary_splits_even_with_small_gap(self):
        events = self.events([{"Timestamp": pd.Timestamp("2025-03-06 12:00:59.999")},
                              {"Timestamp": pd.Timestamp("2025-03-06 12:01:00.000")}])
        groups = correlate(events, [], config={"window_seconds": 60, "max_gap_seconds": 300})
        self.assertEqual(groups.event_count.tolist(), [1, 1])

    def test_future_append_preserves_each_old_event_group_id(self):
        events = self.events([{}, {}, {"User": "bob"}, {}, {"User": "new-user"}])
        before = correlate(events.iloc[:2], [], config=CFG)
        after = correlate(events, [], config=CFG)
        old, new = self.memberships(before), self.memberships(after)
        self.assertEqual(old, {sid: new[sid] for sid in old})
        # Live count legitimately grows, but membership/identity of old rows stays.
        self.assertEqual(before.iloc[0].event_count, 2)
        self.assertEqual(after.loc[after.group_id.eq(before.iloc[0].group_id), "event_count"].iloc[0], 3)

    def test_same_as_of_snapshot_unchanged_when_future_events_and_alerts_added(self):
        events = self.events([{}, {}, {}, {"User": "bob"}])
        point = (events.Timestamp.iloc[1], 1)
        before = correlate(events.iloc[:2], self.pairs(events, [0]), config=CFG, as_of=point)
        after = correlate(events, self.pairs(events, [0, 2]), config=CFG, as_of=point)
        pd.testing.assert_frame_equal(before, after)
        gid = before.group_id.iloc[0]
        pd.testing.assert_frame_equal(
            get_timeline(events.iloc[:2], gid, self.pairs(events, [0]), config=CFG, as_of=point),
            get_timeline(events, gid, self.pairs(events, [0, 2]), config=CFG, as_of=point),
        )

    def test_equal_timestamps_use_record_index_and_causal_cutoff(self):
        events = self.events([{}, {"Timestamp": pd.Timestamp("2025-03-06 12:00:00")},
                              {"Timestamp": pd.Timestamp("2025-03-06 12:00:00")}])
        point = (events.Timestamp.iloc[0], 1)
        before = correlate(events.iloc[:2], [], config=CFG, as_of=point)
        after = correlate(events.iloc[[2, 0, 1]], self.pairs(events, [2]), config=CFG, as_of=point)
        pd.testing.assert_frame_equal(before, after)
        self.assertEqual(after.iloc[0].source_row_ids, events.source_row_id.iloc[:2].tolist())

    def test_alert_count_is_event_count_rule_match_count_preserves_overlap(self):
        events = self.events([{}, {}])
        alerts = self.pairs(events, [0])+self.pairs(events, [0], "RULE_B")+self.pairs(events, [0])
        groups = correlate(events, alerts, config=CFG)
        self.assertEqual(groups.alert_count.iloc[0], 1)
        self.assertEqual(groups.rule_match_count.iloc[0], 2)
        self.assertEqual(groups.rule_ids.iloc[0], ["RULE_A", "RULE_B"])
        merged = [{"source_row_id": events.source_row_id.iloc[0], "rule_ids": ["RULE_A", "RULE_B"]}]
        pd.testing.assert_frame_equal(groups, correlate(events, pd.DataFrame(merged), config=CFG))

    def test_timeline_sorted_raw_preserved_alert_flags_and_no_label(self):
        events = self.events([{}, {}, {}])
        events["Anomaly"] = ["0", "1", "0"]
        before = events.copy(deep=True)
        group = correlate(events.iloc[[2, 0, 1]], self.pairs(events, [1]), config=CFG).iloc[0]
        timeline = get_timeline(events.iloc[[2, 0, 1]], group.group_id, self.pairs(events, [1]), config=CFG)
        self.assertEqual(timeline.source_row_id.tolist(), events.source_row_id.tolist())
        self.assertEqual(timeline.has_alert.tolist(), [False, True, False])
        self.assertEqual(timeline.rule_ids.tolist(), [[], ["RULE_A"], []])
        self.assertNotIn("Anomaly", timeline)
        pd.testing.assert_series_equal(timeline.Full_log, events.Full_log)
        pd.testing.assert_frame_equal(events, before)

    def test_not_run_is_distinct_from_no_alerts(self):
        events = self.events()
        unknown = correlate(events, None, config=CFG)
        complete = correlate(events, [], config=CFG)
        self.assertTrue(pd.isna(unknown.alert_count.iloc[0]))
        self.assertEqual(complete.alert_count.iloc[0], 0)
        timeline = get_timeline(events, unknown.group_id.iloc[0], None, config=CFG)
        self.assertTrue(pd.isna(timeline.has_alert.iloc[0]))
        self.assertFalse(timeline.alerts_evaluated.iloc[0])

    def test_missing_identity_and_invalid_time_not_pooled(self):
        events = self.events([{}, {"User": None}, {"User": " "}, {"Agent_name": ""}, {"Timestamp": pd.NaT}])
        report = {}
        groups = correlate(events, self.pairs(events, [1, 2, 4]), config=CFG, report=report)
        self.assertEqual(groups.event_count.sum(), 1)
        self.assertEqual(report["rows_excluded_missing_user"], 2)
        self.assertEqual(report["rows_excluded_missing_agent"], 1)
        self.assertEqual(report["rows_excluded_invalid_time"], 1)
        self.assertEqual(report["alert_events_excluded_from_grouping"], 3)

    def test_min_events_is_presentation_filter(self):
        events = self.events([{}, {"User": "bob"}, {}])
        report = {}
        groups = correlate(events, [], config={**CFG, "min_events": 2}, report=report)
        self.assertEqual(groups.event_count.tolist(), [2])
        self.assertEqual(report["rows_hidden_min_events"], 1)

    def test_empty_input_and_unknown_timeline(self):
        groups = correlate(self.events([]), [], config=CFG)
        self.assertTrue(groups.empty)
        self.assertEqual(groups.columns.tolist(), list(GROUP_COLUMNS))
        with self.assertRaisesRegex(ValueError, "group_id"):
            get_timeline(self.events(), "does-not-exist", [], config=CFG)

    def test_source_keys_input_attrs_and_config_not_mutated(self):
        events = self.events([{}, {}])
        events.attrs["load_report"] = {"original": [1]}
        before, attrs, config = events.copy(deep=True), copy.deepcopy(events.attrs), CFG.copy()
        correlate(events, [], config=config)
        pd.testing.assert_frame_equal(events, before)
        self.assertEqual(events.attrs, attrs)
        self.assertEqual(config, CFG)
        changed = events.copy()
        changed["Anomaly"] = "anything"
        pd.testing.assert_frame_equal(correlate(events, [], config=CFG), correlate(changed, [], config=CFG))

    def test_missing_columns_bad_metadata_config_and_cutoff_clear_errors(self):
        with self.assertRaisesRegex(ValueError, "User"):
            correlate(self.events().drop(columns="User"))
        for cfg in [{"window_seconds": "bad"}, {"max_gap_seconds": 0}, {"min_events": True}, {"unknown": 1}]:
            with self.subTest(config=cfg), self.assertRaises(ValueError):
                correlate(self.events(), config=cfg)
        for point in [("2025-03-06", -1), "bad-time", pd.Timestamp("2025-03-06", tz="UTC")]:
            with self.subTest(as_of=point), self.assertRaises(ValueError):
                correlate(self.events(), as_of=point)
        events = self.events([{}, {}])
        events["source_row_id"] = "duplicate"
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            correlate(events)

    def test_foreign_alert_mismatched_context_and_bad_merged_list_rejected(self):
        events = self.events()
        for alerts in [[{"source_row_id": "outside", "rule_id": "R"}],
                       [{"source_row_id": events.source_row_id.iloc[0], "rule_ids": '["R"]'}],
                       [{"source_row_id": events.source_row_id.iloc[0], "rule_id": "R", "user": "wrong"}], [{}, {}]]:
            with self.subTest(alerts=alerts), self.assertRaises(ValueError):
                correlate(events, alerts)

    def test_legacy_adapter_uses_last_visible_anchor(self):
        events = self.events([{}, {}])
        result = correlate_events(events, [], config=CFG)
        self.assertEqual(result[0]["anchor_source_row_id"], events.source_row_id.iloc[-1])
        self.assertEqual(result[0]["source_row_ids"], events.source_row_id.tolist())


if __name__ == "__main__":
    unittest.main()
