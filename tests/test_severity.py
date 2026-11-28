"""Policy boundaries, causal prefix context, raw/label/ML independence."""
import copy
import unittest

import pandas as pd

from detection.alert_aggregation import merge_alerts, validate_merged_alert
from detection.correlation import correlate, correlate_events
from detection.severity import assign_severity, load_severity_config


class SeverityTests(unittest.TestCase):
    def events(self, count=10, hour=12):
        return pd.DataFrame({
            "Timestamp": [pd.Timestamp(f"2025-03-06 {hour:02d}:00:00")+pd.Timedelta(seconds=i) for i in range(count)],
            "User": ["alice"]*count, "Agent_name": ["host"]*count,
            "Activity": ["command"]*count, "record_index": list(range(count)),
            "source_row_id": ["a"*64+f":{i:08d}" for i in range(count)],
            "Full_log": [' Raw "mixed",\r\n ']*count, "Description": [" NA "]*count, "Content": [""]*count,
        })

    def alerts(self, events, rule="CMD_JOHN"):
        return [{"alert_id": r.source_row_id+":"+rule, "source_row_id": r.source_row_id,
                 "timestamp": r.Timestamp.isoformat(timespec="milliseconds"), "user": r.User,
                 "agent": r.Agent_name, "activity": r.Activity, "rule_id": rule,
                 "reason": "matched field and value", "evidence": {"Full_log": r.Full_log, "Description": r.Description, "Content": r.Content},
                 "severity": "LOW", "severity_reason": "incoming level must not drive policy"}
                for r in events.itertuples()]

    def test_all_four_levels(self):
        events = self.events()
        scored = assign_severity(self.alerts(events), events=events)
        self.assertEqual([scored[i]["severity"] for i in [0, 2, 9]], ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertEqual(assign_severity(self.alerts(events.iloc[:1], "HTTP_IP_HOST"))[0]["severity"], "LOW")

    def test_alert_count_boundaries_two_three_nine_ten(self):
        events = self.events()
        out = assign_severity(self.alerts(events), events=events)
        self.assertEqual([out[i]["severity"] for i in [1, 2, 8, 9]], ["MEDIUM", "HIGH", "HIGH", "CRITICAL"])
        self.assertIn("3 alerted events (+1)", out[2]["severity_reason"])

    def test_working_hour_boundaries(self):
        for stamp, expected in [("07:59:59.999", "HIGH"), ("08:00:00.000", "MEDIUM"),
                                ("17:59:59.999", "MEDIUM"), ("18:00:00.000", "HIGH")]:
            with self.subTest(stamp=stamp):
                event = self.events(1)
                event.loc[0, "Timestamp"] = pd.Timestamp("2025-03-06 "+stamp)
                self.assertEqual(assign_severity(self.alerts(event))[0]["severity"], expected)

    def test_activity_counts_only_prefix_and_unalerted_context(self):
        events = self.events(4)
        events["Activity"] = ["command", "file", "http", "http"]
        alerts = self.alerts(events.iloc[[0, 2, 3]])
        out = assign_severity(alerts, events=events)
        self.assertEqual(out[0]["severity"], "MEDIUM")
        self.assertEqual(out[1]["severity"], "HIGH")  # two alert events + three activities
        self.assertEqual(out[2]["severity"], "CRITICAL")
        self.assertIn("3 activity types (+1)", out[1]["severity_reason"])

    def test_activity_name_alone_does_not_change_priority(self):
        events = self.events(1)
        events["Activity"] = "attack"
        self.assertEqual(assign_severity(self.alerts(events), events=events)[0]["severity"], "MEDIUM")

    def test_future_append_does_not_rescore_past(self):
        full = self.events()
        full["Activity"] = ["command"]*2+["file", "http"]+["session"]*6
        early = full.iloc[:2].copy()
        first = assign_severity(self.alerts(early), correlate(early, []), events=early)
        all_results = assign_severity(self.alerts(full), correlate(full, []), events=full)
        self.assertEqual(first, all_results[:2])

    def test_same_timestamp_tie_respects_record_index_not_input_order(self):
        events = self.events(3)
        events["Timestamp"] = events.Timestamp.iloc[0]
        alerts = self.alerts(events)
        out = assign_severity(alerts[::-1], events=events.iloc[::-1])
        by_id = {a["source_row_id"]: a["severity"] for a in out}
        self.assertEqual([by_id[s] for s in events.source_row_id], ["MEDIUM", "MEDIUM", "HIGH"])

    def test_duplicate_delivery_and_multi_rule_count_as_one_event(self):
        events = self.events(2)
        alerts = self.alerts(events)
        other = self.alerts(events.iloc[:1], "CMD_NMAP")
        out = assign_severity(alerts+other+[copy.deepcopy(alerts[0])], events=events)
        self.assertTrue(all(a["severity"] == "MEDIUM" for a in out))
        self.assertIn("2 alerted events (+0)", out[1]["severity_reason"])

    def test_user_agent_separation_and_gap_window_reset(self):
        for change in ("user", "agent", "gap", "bucket"):
            with self.subTest(change=change):
                events = self.events(3)
                if change == "user": events.loc[2, "User"] = "bob"
                elif change == "agent": events.loc[2, "Agent_name"] = "other-host"
                elif change == "gap": events.loc[2, "Timestamp"] += pd.Timedelta(seconds=301)
                else: events.loc[2, "Timestamp"] = pd.Timestamp("2025-03-06 12:15:00")
                out = assign_severity(self.alerts(events), events=events)
                self.assertEqual(out[2]["severity"], "MEDIUM")

    def test_missing_user_retains_alert_no_synthetic_group(self):
        events = self.events(3)
        events["User"] = None
        out = assign_severity(self.alerts(events), events=events)
        self.assertTrue(all(a["severity"] == "MEDIUM" for a in out))
        self.assertIn("no eligible group context", out[0]["severity_reason"])

    def test_missing_event_schema_and_unknown_source_context_raise(self):
        events = self.events(1)
        alerts = self.alerts(events)
        with self.assertRaisesRegex(ValueError, "record_index"):
            assign_severity(alerts, events=events.drop(columns="record_index"))
        bad = copy.deepcopy(alerts)
        bad[0]["user"] = "wrong"
        with self.assertRaisesRegex(ValueError, "does not match"):
            assign_severity(bad, events=events)
        with self.assertRaisesRegex(ValueError, "not found"):
            assign_severity(self.alerts(self.events(2)), events=events)

    def test_correlations_need_events_and_correct_membership(self):
        events = self.events(3)
        alerts = self.alerts(events)
        groups = correlate(events, [])
        with self.assertRaisesRegex(ValueError, "events"):
            assign_severity(alerts, groups)
        wrong = groups.copy(deep=True)
        wrong.at[0, "source_row_ids"] = events.source_row_id.tolist()[:1]
        with self.assertRaisesRegex(ValueError, "snapshot"):
            assign_severity(alerts, wrong, events=events)
        # Aggregate totals are never used, even if supplied summaries change.
        wrong = groups.copy(deep=True)
        wrong["alert_count"] = 999999
        wrong["activities"] = [["invented"]]
        self.assertEqual(assign_severity(alerts, wrong, events=events), assign_severity(alerts, events=events))

    def test_adapter_and_empty_correlations(self):
        events = self.events(3)
        alerts = self.alerts(events)
        self.assertEqual(assign_severity(alerts, correlate_events(events, [], config=load_severity_config()["correlation"]), events=events), assign_severity(alerts, events=events))
        self.assertEqual(assign_severity(alerts, [], events=events)[2]["severity"], "MEDIUM")

    def test_ml_argument_is_not_inspected(self):
        class Poison:
            def __bool__(self): raise AssertionError("ML must not be inspected")
            def __iter__(self): raise AssertionError("ML must not be iterated")
        alerts = self.alerts(self.events(1))
        self.assertEqual(assign_severity(alerts), assign_severity(alerts, ml_results=Poison()))

    def test_labels_and_level_not_used(self):
        events = self.events(3)
        alerts = self.alerts(events)
        baseline = assign_severity(alerts, events=events)
        events["Anomaly"] = [0, 1, "malformed"]
        events["Level"] = [999, -500, 0]
        self.assertEqual(baseline, assign_severity(alerts, events=events))

    def test_input_raw_and_detection_reason_unchanged_idempotence(self):
        events = self.events(3, hour=20)
        alerts = self.alerts(events)
        original, frame = copy.deepcopy(alerts), events.copy(deep=True)
        scored = assign_severity(alerts, events=events)
        self.assertEqual(alerts, original)
        pd.testing.assert_frame_equal(events, frame)
        for before, after in zip(alerts, scored):
            self.assertEqual(before["evidence"], after["evidence"])
            self.assertEqual(before["reason"], after["reason"])
        scored[0]["evidence"]["Full_log"] = "mutated"
        self.assertEqual(alerts, original)
        scored = assign_severity(alerts, events=events)
        self.assertEqual(scored, assign_severity(scored, events=events))

    def test_policy_cap_custom_thresholds_and_disable_context(self):
        events = self.events(3, hour=22)
        events["Activity"] = ["command", "file", "http"]
        config = load_severity_config()
        out = assign_severity(self.alerts(events), events=events, config=config)
        self.assertEqual(out[-1]["severity"], "CRITICAL")
        self.assertIn("total increase=2", out[-1]["severity_reason"])
        config["max_context_steps"] = 0
        self.assertEqual(assign_severity(self.alerts(events), events=events, config=config)[-1]["severity"], "MEDIUM")
        config["max_context_steps"], config["off_hours_steps"] = 3, 0
        config["activity_steps"] = 0
        config["alert_thresholds"] = [{"count": 2, "steps": 2}]
        self.assertEqual(assign_severity(self.alerts(events), events=events, config=config)[1]["severity"], "CRITICAL")

    def test_invalid_policy(self):
        for field, value in [("working_hour_start", 18), ("off_hours_steps", True), ("max_context_steps", -1),
                             ("activity_threshold", 1), ("alert_thresholds", [{"count": 3, "steps": 1}, {"count": 2, "steps": 2}]),
                             ("correlation", {"window_seconds": -1}), ("unexpected", 1)]:
            with self.subTest(field=field):
                config = load_severity_config()
                config[field] = value
                with self.assertRaises(ValueError): load_severity_config(config)

    def test_empty_unknown_rule_conflicts_and_merged_input(self):
        self.assertEqual(assign_severity([]), [])
        alerts = self.alerts(self.events(1), "UNKNOWN_RULE")
        with self.assertRaisesRegex(ValueError, "UNKNOWN_RULE"): assign_severity(alerts)
        alerts = self.alerts(self.events(1))
        duplicate = copy.deepcopy(alerts[0])
        duplicate["reason"] = "conflict"
        with self.assertRaises(ValueError): assign_severity(alerts+[duplicate])
        with self.assertRaises(ValueError): assign_severity(merge_alerts(alerts))

    def test_scored_atomic_can_merge_with_frozen_schema(self):
        events = self.events(3)
        scored = assign_severity(self.alerts(events), events=events)
        for merged in merge_alerts(scored): validate_merged_alert(merged)


if __name__ == "__main__":
    unittest.main()
