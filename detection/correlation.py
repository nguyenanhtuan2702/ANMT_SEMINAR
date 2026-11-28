"""Causal event grouping by actor, fixed time window, and inter-event gap."""
from __future__ import annotations

import hashlib

import pandas as pd

from preprocessing.source_ids import validate_source_row_ids


GROUP_COLUMNS = [
    "group_id",
    "key",
    "user",
    "agent",
    "start_time",
    "end_time",
    "event_count",
    "activities",
    "alert_count",
    "rule_match_count",
    "rule_ids",
    "source_row_ids",
]


def correlate_events(
    events: pd.DataFrame,
    alerts: pd.DataFrame | None = None,
    *,
    window_seconds: int = 900,
    max_gap_seconds: int = 300,
    min_events: int = 1,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return events with group IDs and a timeline summary for each group."""
    if window_seconds <= 0 or max_gap_seconds < 0 or min_events < 1:
        raise ValueError("Tham số correlation phải là số dương hợp lệ.")
    required = {"source_row_id", "Timestamp", "User", "Agent_name", "Activity"}
    missing = required - set(events.columns)
    if missing:
        raise ValueError(
            "Correlation thiếu cột bắt buộc: " + ", ".join(sorted(missing))
        )
    events = events.copy()
    events["source_row_id"] = validate_source_row_ids(
        events,
        component="Correlation",
    )

    if alerts is None:
        alerts = pd.DataFrame(columns=["source_row_id", "rule_id"])
    if not alerts.empty and "source_row_id" not in alerts.columns:
        raise ValueError("Alerts cần có cột source_row_id.")
    event_alerts = index_alerts_by_source(alerts)
    alert_source_ids = set(event_alerts)
    result = events.copy()
    result["group_id"] = pd.Series(pd.NA, index=result.index, dtype="string")

    eligible = result[
        result["Timestamp"].notna()
        & result["User"].notna()
        & result["Agent_name"].notna()
        & result["User"].astype("string").str.strip().ne("")
        & result["Agent_name"].astype("string").str.strip().ne("")
    ]
    work_columns = [
        "source_row_id",
        "Timestamp",
        "User",
        "Agent_name",
        "Activity",
    ]
    if "record_index" in result.columns:
        work_columns.append("record_index")
    work = eligible[work_columns].copy()
    work["_bucket"] = (
        work["Timestamp"].astype("datetime64[ns]").astype("int64")
        // (window_seconds * 1_000_000_000)
    )
    actor_keys = ["User", "Agent_name", "_bucket"]
    order_columns = actor_keys + ["Timestamp"]
    if "record_index" in work.columns:
        order_columns.append("record_index")
    work = work.sort_values(order_columns, kind="stable")
    time_gaps = work.groupby(actor_keys, sort=False)["Timestamp"].diff()
    work["_segment"] = (
        time_gaps.gt(pd.Timedelta(seconds=max_gap_seconds))
        .groupby([work[column] for column in actor_keys], sort=False)
        .cumsum()
        .astype("int64")
    )
    segment_keys = actor_keys + ["_segment"]
    summary = (
        work.groupby(segment_keys, sort=False, dropna=True)
        .agg(
            start_time=("Timestamp", "first"),
            end_time=("Timestamp", "last"),
            event_count=("source_row_id", "size"),
            activities=(
                "Activity",
                lambda values: sorted({
                    str(value)
                    for value in values
                    if pd.notna(value) and str(value).strip()
                }),
            ),
            source_row_ids=("source_row_id", list),
        )
        .reset_index()
    )

    groups = []
    id_map = {}
    for row in summary.loc[summary["event_count"] >= min_events].to_dict("records"):
        user = row["User"]
        agent = row["Agent_name"]
        bucket = row["_bucket"]
        row_ids = [str(source_id) for source_id in row["source_row_ids"]]
        group_seed = "\0".join(
            (str(user), str(agent), str(bucket), row_ids[0])
        ).encode("utf-8")
        group_id = "grp-" + hashlib.sha256(group_seed).hexdigest()[:16]
        id_map.update({source_id: group_id for source_id in row_ids})
        source_ids = set(row_ids)
        rule_ids = sorted({
            rule_id
            for source_id in source_ids
            for rule_id in event_alerts.get(source_id, set())
        })
        groups.append(
            {
                "group_id": group_id,
                "key": {"user": str(user), "agent": str(agent)},
                "user": user,
                "agent": agent,
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "event_count": row["event_count"],
                "activities": row["activities"],
                "alert_count": len(source_ids & alert_source_ids),
                "rule_match_count": sum(
                    len(event_alerts.get(source_id, set()))
                    for source_id in source_ids
                ),
                "rule_ids": rule_ids,
                "source_row_ids": row_ids,
            }
        )
    result["group_id"] = result["source_row_id"].astype(str).map(id_map).astype("string")
    group_frame = pd.DataFrame(groups, columns=GROUP_COLUMNS)
    if not group_frame.empty:
        group_frame = group_frame.sort_values(
            ["start_time", "group_id"], kind="stable"
        ).reset_index(drop=True)
    return result, group_frame


def index_alerts_by_source(alerts: pd.DataFrame) -> dict[str, set[str]]:
    """Index alert rule IDs by source event without mutating the input."""
    indexed: dict[str, set[str]] = {}
    if alerts.empty:
        return indexed
    if "rule_id" not in alerts.columns:
        raise ValueError("Alerts cần có cột rule_id.")
    source_ids = validate_source_row_ids(
        alerts,
        component="Correlation alerts",
        unique=False,
    )
    for source_id, rule_id in zip(
        source_ids,
        alerts["rule_id"],
    ):
        indexed.setdefault(str(source_id), set()).add(str(rule_id))
    return indexed
