import unittest

import pandas as pd

from evaluation.rule_metrics import evaluate_rule_alerts
from evaluation.verify_rules import select_samples


class RuleMetricsTests(unittest.TestCase):
    def events(self):
        return pd.DataFrame({"source_row_id": ["a", "b", "c", "d"], "Anomaly": ["1", "0", "1", "0"]})

    def test_confusion_matrix_and_union_count_unique_events(self):
        alerts = [{"rule_id": "R_A", "source_row_id": "a"}, {"rule_id": "R_A", "source_row_id": "a"},
                  {"rule_id": "R_A", "source_row_id": "b"}, {"rule_id": "R_B", "source_row_id": "a"},
                  {"rule_id": "R_B", "source_row_id": "c"}]
        result = evaluate_rule_alerts(self.events(), alerts, ["R_A", "R_B"]).set_index("rule_id")
        self.assertEqual(result.loc["R_A", ["tp", "fp", "fn", "tn"]].tolist(), [1, 1, 1, 1])
        self.assertEqual(result.loc["R_A", "alert_records"], 3)
        self.assertEqual(result.loc["R_A", "unique_alert_events"], 2)
        self.assertEqual(result.loc["R_A", "precision"], 0.5)
        self.assertEqual(result.loc["R_A", "recall"], 0.5)
        self.assertEqual(result.loc["__UNION__", ["tp", "fp", "fn", "tn"]].tolist(), [2, 1, 0, 1])

    def test_unknown_labels_excluded_not_filled_benign(self):
        source = pd.DataFrame({"source_row_id": ["a", "b", "c"], "Anomaly": [None, "unknown", " 1 "]})
        result = evaluate_rule_alerts(source, [{"rule_id": "R", "source_row_id": "a"}], ["R"]).iloc[0]
        self.assertEqual(result.excluded_label_events, 2)
        self.assertEqual(result.evaluated_alert_events, 0)
        self.assertEqual(result.fp, 0)
        self.assertTrue(pd.isna(result.precision))
        self.assertEqual(result.recall, 0)

    def test_zero_alerts_precision_undefined_recall_zero(self):
        result = evaluate_rule_alerts(self.events(), [], ["R"]).iloc[0]
        self.assertTrue(pd.isna(result.precision))
        self.assertEqual(result.recall, 0)
        self.assertEqual(result.fn, 2)

    def test_no_positives_recall_undefined(self):
        source = self.events()
        source["Anomaly"] = "0"
        result = evaluate_rule_alerts(source, [{"rule_id": "R", "source_row_id": "a"}], ["R"]).iloc[0]
        self.assertTrue(pd.isna(result.recall))
        self.assertEqual(result.precision, 0)

    def test_missing_columns_duplicate_ids_or_foreign_alert_rejected(self):
        with self.assertRaisesRegex(ValueError, "Anomaly"):
            evaluate_rule_alerts(self.events().drop(columns="Anomaly"), [], ["R"])
        source = self.events()
        source["source_row_id"] = "duplicate"
        with self.assertRaises(ValueError):
            evaluate_rule_alerts(source, [], ["R"])
        with self.assertRaisesRegex(ValueError, "cannot be joined"):
            evaluate_rule_alerts(self.events(), [{"rule_id": "R", "source_row_id": "outside"}], ["R"])

    def test_sampling_reproducible_label_blind_and_takes_all_small_pools(self):
        alerts = [{"rule_id": "R", "source_row_id": str(i)} for i in range(40)]
        selected = select_samples(alerts, "R")
        self.assertEqual(len(selected), 25)
        self.assertEqual(selected, select_samples(list(reversed(alerts)), "R"))
        labeled = [{**a, "Anomaly": "0"} for a in alerts]
        self.assertEqual([a["source_row_id"] for a in selected], [a["source_row_id"] for a in select_samples(labeled, "R")])
        self.assertEqual(len(select_samples(alerts[:8], "R")), 8)


if __name__ == "__main__":
    unittest.main()
