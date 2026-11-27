"""Reference-label scoring only; never imported by detection modules."""
from __future__ import annotations

import pandas as pd


def evaluate_rule_alerts(events: pd.DataFrame, alerts: list[dict], rule_ids: list[str]) -> pd.DataFrame:
    """Metrics per unique event, plus union; recall denominator is all label=1 rows.

    Unknown/missing labels are excluded and counted, never filled as benign.
    Undefined precision/recall/F1 use None, not a fabricated zero/one. Duplicate
    delivery or overlap cannot inflate TP counts. Every alert must join exactly
    one source_row_id in the evaluation dataset.
    """
    missing = sorted({"source_row_id", "Anomaly"} - set(events.columns))
    if missing:
        raise ValueError("Evaluation is missing columns: " + ", ".join(missing))
    keys = events["source_row_id"]
    if keys.isna().any() or keys.duplicated().any() or not keys.map(lambda x: isinstance(x, str) and bool(x.strip())).all():
        raise ValueError("Evaluation source_row_id values must be unique and nonempty.")
    if len(rule_ids) != len(set(rule_ids)) or "__UNION__" in rule_ids:
        raise ValueError("Invalid evaluation rule_ids list.")
    known = set(keys)
    predictions = {rid: set() for rid in rule_ids}
    records = {rid: 0 for rid in rule_ids}
    for alert in alerts:
        if alert["source_row_id"] not in known:
            raise ValueError("Alert cannot be joined to the dataset: "+str(alert["source_row_id"]))
        if alert["rule_id"] not in predictions:
            raise ValueError("Rule is not in the evaluation list: "+str(alert["rule_id"]))
        predictions[alert["rule_id"]].add(alert["source_row_id"])
        records[alert["rule_id"]] += 1
    labels = events["Anomaly"].astype("string").str.strip()
    positives = set(keys[labels.eq("1").fillna(False)])
    negatives = set(keys[labels.eq("0").fillna(False)])
    valid = positives | negatives
    predictions["__UNION__"] = set().union(*predictions.values()) if predictions else set()
    records["__UNION__"] = len(alerts)
    rows = []
    for rid, predicted in predictions.items():
        tp, fp = len(predicted & positives), len(predicted & negatives)
        fn, tn = len(positives - predicted), len(negatives - predicted)
        precision = tp/(tp+fp) if tp+fp else None
        recall = tp/(tp+fn) if tp+fn else None
        f1 = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
        rows.append({"rule_id": rid, "alert_records": records[rid], "unique_alert_events": len(predicted),
                     "evaluated_alert_events": len(predicted & valid), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                     "precision": precision, "label_match_rate": precision, "recall": recall, "f1": f1,
                     "reference_positive_events": len(positives), "reference_negative_events": len(negatives),
                     "excluded_label_events": len(known-valid)})
    return pd.DataFrame(rows)
