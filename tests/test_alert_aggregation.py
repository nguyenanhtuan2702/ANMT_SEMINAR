import copy
import hashlib
import json
from pathlib import Path
import unittest

from detection.alert_aggregation import (
    MERGED_ALERT_COLUMNS, merge_alerts, merged_alerts_to_dataframe,
    validate_atomic_alert, validate_merged_alert,
)
from detection.rule_engine import ALERT_COLUMNS


class AlertAggregationTests(unittest.TestCase):
    def alert(self, rule="RULE_A", index=0, severity="LOW"):
        sid = "a"*64+f":{index:08d}"
        return {"alert_id": sid+":"+rule, "source_row_id": sid,
                "timestamp": "2025-03-06T12:00:00.000", "user": None,
                "agent": "host", "activity": "command", "rule_id": rule,
                "reason": "Command='nmap'", "severity": severity,
                "severity_reason": "Prototype priority only", "evidence": {"Full_log": ' Raw "text"\n ', "Content": ""}}

    def test_multiple_rules_merge_with_sorted_ids_all_evidence_and_max_priority(self):
        first, second = self.alert("RULE_B", severity="HIGH"), self.alert("RULE_A")
        result = merge_alerts([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule_ids"], ["RULE_A", "RULE_B"])
        self.assertEqual(result[0]["severity"], "HIGH")
        self.assertEqual(result[0]["rule_matches"][1]["evidence"], first["evidence"])
        self.assertIn("RULE_A", result[0]["reason"])
        validate_merged_alert(result[0])

    def test_exact_duplicates_idempotent_and_order_independent(self):
        first, second = self.alert(), self.alert("RULE_B")
        self.assertEqual(merge_alerts([first, second, first]), merge_alerts([second, first]))

    def test_conflicting_repeated_rule_rejected(self):
        first = self.alert()
        second = copy.deepcopy(first)
        second["reason"] = "different"
        with self.assertRaisesRegex(ValueError, "Duplicate alert key"):
            merge_alerts([first, second])

    def test_conflicting_context_same_source_rejected(self):
        first, second = self.alert(), self.alert("RULE_B")
        second["agent"] = "other"
        with self.assertRaisesRegex(ValueError, "Inconsistent event context"):
            merge_alerts([first, second])

    def test_same_raw_on_distinct_rows_is_not_collapsed(self):
        result = merge_alerts([self.alert(index=1), self.alert(index=0)])
        self.assertEqual(len(result), 2)
        self.assertTrue(result[0]["source_row_id"].endswith(":00000000"))

    def test_no_input_mutation_or_evidence_aliasing(self):
        first = self.alert()
        before = copy.deepcopy(first)
        result = merge_alerts([first])
        result[0]["rule_matches"][0]["evidence"]["Full_log"] = "changed"
        self.assertEqual(first, before)

    def test_schema_rejects_labels_invalid_times_and_keys(self):
        for mutation in ("label", "level", "timestamp", "source", "severity", "extra"):
            alert = self.alert()
            if mutation == "label": alert["evidence"]["Anomaly"] = "1"
            elif mutation == "level": alert["evidence"]["Level"] = "12"
            elif mutation == "timestamp": alert["timestamp"] = "2025-03-06T12:00:00.000Z"
            elif mutation == "source": alert["source_row_id"] = "opaque"
            elif mutation == "severity": alert["severity"] = None
            else: alert["Anomaly"] = "1"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_atomic_alert(alert)

    def test_merged_schema_cross_field_invariants(self):
        for mutation in ("rules", "severity", "reason", "version"):
            merged = merge_alerts([self.alert()])[0]
            if mutation == "rules": merged["rule_ids"] = ["RULE_X"]
            elif mutation == "severity": merged["severity"] = "CRITICAL"
            elif mutation == "reason": merged["reason"] = "lost evidence"
            else: merged["schema_version"] = "2.0"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_merged_alert(merged)

    def test_empty_and_populated_dataframe_keep_frozen_schema(self):
        self.assertEqual(merged_alerts_to_dataframe([]).columns.tolist(), list(MERGED_ALERT_COLUMNS))
        frame = merged_alerts_to_dataframe(merge_alerts([self.alert()]))
        self.assertEqual(frame.rule_ids.iloc[0], ["RULE_A"])
        self.assertEqual(frame.schema_version.iloc[0], "1.0")

    def test_english_summary_rejects_arbitrary_or_empty_replacements(self):
        merged = merge_alerts([self.alert()])[0]
        self.assertIn("Highest prototype priority", merged["severity_reason"])
        for reason in ("", " ", None, "arbitrary summary", 123):
            modified = copy.deepcopy(merged)
            modified["severity_reason"] = reason
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                validate_merged_alert(modified)

    def test_machine_schema_matches_exported_field_sets(self):
        schema = json.loads(Path("docs/schemas/alert_v1.0.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), set(MERGED_ALERT_COLUMNS))
        self.assertEqual(set(schema["$defs"]["atomic_alert"]["required"]), set(ALERT_COLUMNS))
        self.assertFalse(schema["additionalProperties"])
        freeze = json.loads(Path("docs/schemas/alert_v1.0.freeze.json").read_text(encoding="utf-8"))
        self.assertEqual(freeze["schema_sha256"], hashlib.sha256(Path("docs/schemas/alert_v1.0.schema.json").read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
