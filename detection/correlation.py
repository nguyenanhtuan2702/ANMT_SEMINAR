"""Causal fixed-window sessions, grouped by User then Agent_name.

Membership uses groupby/diff/cumsum/transform; no event-row Python loop. Live
group summaries grow as events arrive; use as_of=(Timestamp, record_index) for
an immutable historical snapshot, including ties at the same timestamp.
"""
from __future__ import annotations

import time
from numbers import Integral

import pandas as pd

from preprocessing.contracts import Alert, Correlation, CorrelationConfig

DEFAULT_CONFIG = {"window_seconds": 900, "max_gap_seconds": 300, "min_events": 1}
GROUP_COLUMNS = (
    "group_id", "key", "user", "agent", "start_time", "end_time", "event_count",
    "activities", "alert_count", "rule_match_count", "rule_ids", "source_row_ids",
)
CORE = ("Timestamp", "User", "Agent_name", "Activity", "source_row_id", "record_index")
TIMELINE_COLUMNS = ("group_id", "has_alert", "alert_count", "rule_match_count", "rule_ids", "alerts_evaluated")


def _identifier_isin(values: pd.Series, candidates: pd.Series) -> pd.Series:
    """Hash string IDs without repeated Arrow scalar conversion in pandas 3.

    These identifiers are validated separately; no identity or grouping semantics
    change. Temporary object arrays are only used for membership/list aggregation.
    """
    return values.astype(object).isin(candidates.to_numpy(dtype=object))


def _config(config: CorrelationConfig | None) -> dict:
    result = dict(DEFAULT_CONFIG)
    if config is not None:
        if not isinstance(config, dict) or set(config) - set(DEFAULT_CONFIG):
            raise ValueError("Correlation config only accepts window_seconds, max_gap_seconds, min_events.")
        result.update(config)
    for key, value in result.items():
        if type(value) is not int or value <= 0:
            raise ValueError(f"{key} must be a positive integer.")
    if config is not None and "window_seconds" in config and "max_gap_seconds" not in config:
        result["max_gap_seconds"] = min(DEFAULT_CONFIG["max_gap_seconds"], result["window_seconds"])
    try:
        pd.Timedelta(seconds=result["window_seconds"])
        pd.Timedelta(seconds=result["max_gap_seconds"])
    except (ValueError, OverflowError) as error:
        raise ValueError("Correlation window is outside the Timedelta range.") from error
    return result


def _cutoff(as_of):
    if as_of is None:
        return None, None
    index = None
    if isinstance(as_of, tuple):
        if len(as_of) != 2 or not isinstance(as_of[1], Integral) or isinstance(as_of[1], bool) or as_of[1] < 0:
            raise ValueError("as_of tuples require (Timestamp, nonnegative integer record_index).")
        as_of, index = as_of[0], int(as_of[1])
    try:
        timestamp = pd.Timestamp(as_of)
    except (ValueError, TypeError) as error:
        raise ValueError("as_of is not a valid Timestamp.") from error
    if pd.isna(timestamp) or timestamp.tzinfo is not None:
        raise ValueError("as_of must be a nonmissing, timezone-naive Timestamp.")
    return timestamp, index


def _sessionize(logs: pd.DataFrame, config: dict, as_of) -> tuple[pd.DataFrame, dict]:
    if not isinstance(logs, pd.DataFrame):
        raise TypeError("Correlation requires a pandas DataFrame from the normalizer.")
    if not logs.columns.is_unique:
        raise ValueError("Correlation: duplicate column names.")
    missing = sorted(set(CORE) - set(logs.columns))
    if missing:
        raise ValueError("Correlation is missing columns: " + ", ".join(missing))
    collision = sorted(set(TIMELINE_COLUMNS).intersection(logs.columns))
    if collision:
        raise ValueError("Input contains reserved timeline columns: " + ", ".join(collision))
    if not pd.api.types.is_datetime64_any_dtype(logs["Timestamp"]) or logs["Timestamp"].dt.tz is not None:
        raise ValueError("Timestamp must be timezone-naive datetime from the normalizer.")
    ids, indices = logs["source_row_id"], logs["record_index"]
    if ids.isna().any() or ids.duplicated().any() or not ids.map(lambda value: isinstance(value, str) and bool(value.strip())).astype(bool).all():
        raise ValueError("source_row_id requires unique, nonempty, nonmissing strings.")
    if (not pd.api.types.is_integer_dtype(indices.dtype) or pd.api.types.is_bool_dtype(indices.dtype)
            or indices.isna().any() or indices.lt(0).any() or indices.duplicated().any()):
        raise ValueError("record_index requires unique nonnegative integers within the file.")
    # Only non-label columns enter correlation/timeline, including raw evidence.
    frame = logs.loc[:, [c for c in logs.columns if c != "Anomaly"]].copy()
    frame.attrs = {}
    timestamp, index = _cutoff(as_of)
    visible = pd.Series(True, index=frame.index)
    if timestamp is not None:
        visible = frame["Timestamp"].le(timestamp)
        if index is not None:
            visible &= frame["Timestamp"].lt(timestamp) | frame["record_index"].le(index)
    frame = frame.loc[visible].copy()
    valid_time = frame["Timestamp"].notna()
    if "invalid_timestamp" in frame:
        if not pd.api.types.is_bool_dtype(frame["invalid_timestamp"]):
            raise ValueError("invalid_timestamp must be boolean.")
        valid_time &= ~frame["invalid_timestamp"].fillna(True)
    valid_user = frame["User"].astype("string").str.strip().ne("").fillna(False)
    valid_agent = frame["Agent_name"].astype("string").str.strip().ne("").fillna(False)
    info = {"rows_input": len(logs), "rows_visible": len(frame),
            "rows_excluded_invalid_time": int((~valid_time).sum()),
            "rows_excluded_missing_user": int((~valid_user).sum()),
            "rows_excluded_missing_agent": int((~valid_agent).sum()),
            "as_of_time": timestamp.isoformat() if timestamp is not None else None,
            "as_of_record_index": index, "config": config.copy()}
    frame = frame.loc[valid_time & valid_user & valid_agent].sort_values(["Timestamp", "record_index"], kind="stable").reset_index(drop=True)
    # Fixed buckets are left-closed/right-open, aligned to epoch in source clock.
    frame["_corr_bucket"] = frame["Timestamp"].dt.floor(pd.Timedelta(seconds=config["window_seconds"]))
    keys = ["User", "Agent_name", "_corr_bucket"]
    gap = frame.groupby(keys, sort=False, dropna=False)["Timestamp"].diff()
    starts = gap.isna() | gap.gt(pd.Timedelta(seconds=config["max_gap_seconds"]))
    frame["_corr_segment"] = starts.groupby([frame[c] for c in keys], sort=False, dropna=False).cumsum().astype("int64")
    first = frame.groupby([*keys, "_corr_segment"], sort=False, dropna=False)["source_row_id"].transform("first")
    # No ordinal/ngroup ID: future groups for other users cannot renumber old IDs.
    namespace = f"corr:v1:w{config['window_seconds']}:g{config['max_gap_seconds']}:"
    frame["group_id"] = (namespace + first.astype("string")).astype("string")
    info["rows_grouped"] = len(frame)
    info["rows_excluded_unique"] = info["rows_visible"]-len(frame)
    return frame, info


def _alert_pairs(alerts, logs: pd.DataFrame) -> pd.DataFrame | None:
    if alerts is None:
        return None
    if isinstance(alerts, pd.DataFrame):
        data = alerts.copy()
        data.attrs = {}
    elif isinstance(alerts, list):
        data = pd.DataFrame(alerts)
    else:
        raise TypeError("alerts must be an atomic/merged list, a DataFrame, or None.")
    if len(data) == 0:
        return pd.DataFrame({"source_row_id": pd.Series(dtype="string"), "rule_id": pd.Series(dtype="string")})
    missing = {"source_row_id"} - set(data.columns)
    if missing or ("rule_id" not in data and "rule_ids" not in data):
        raise ValueError("Alerts require source_row_id and rule_id (atomic) or rule_ids (merged).")
    if "rule_id" in data and "rule_ids" in data:
        raise ValueError("Do not mix atomic and merged formats in the same call.")
    if data["source_row_id"].isna().any() or not _identifier_isin(data["source_row_id"], logs["source_row_id"]).all():
        raise ValueError("Alert source_row_id cannot be joined to logs.")
    # Check shared fields if supplied; avoid attaching an alert to a different event.
    reference = logs.set_index("source_row_id")
    for field, source in (("timestamp", "Timestamp"), ("user", "User"), ("agent", "Agent_name"), ("activity", "Activity")):
        if field in data:
            expected = data["source_row_id"].map(reference[source])
            if field == "timestamp":
                expected = expected.dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3]
            actual = data[field].astype("string").reset_index(drop=True)
            expected = expected.astype("string").reset_index(drop=True)
            if not (actual.eq(expected) | (actual.isna() & expected.isna())).fillna(False).all():
                raise ValueError(f"Alert {field} does not match the source event.")
    if "rule_ids" in data:
        if not data["rule_ids"].map(lambda value: isinstance(value, list) and bool(value)).all():
            raise ValueError("Merged rule_ids must be a nonempty list (decode JSON strings first).")
        data = data[["source_row_id", "rule_ids"]].explode("rule_ids").rename(columns={"rule_ids": "rule_id"})
    pairs = data[["source_row_id", "rule_id"]].copy()
    if not pairs["rule_id"].map(lambda value: isinstance(value, str) and bool(value.strip())).all():
        raise ValueError("Alert rule_id must be a nonempty string.")
    return pairs.drop_duplicates().sort_values(["source_row_id", "rule_id"], kind="stable").reset_index(drop=True)


def _annotate(frame: pd.DataFrame, pairs: pd.DataFrame | None) -> pd.DataFrame:
    frame = frame.copy()
    if pairs is None:
        frame["alerts_evaluated"] = False
        frame["has_alert"] = pd.Series(pd.NA, index=frame.index, dtype="boolean")
        frame["alert_count"] = pd.Series(pd.NA, index=frame.index, dtype="Int64")
        frame["rule_match_count"] = pd.Series(pd.NA, index=frame.index, dtype="Int64")
        frame["rule_ids"] = [[] for _ in range(len(frame))]
    else:
        counts = pairs.groupby("source_row_id", sort=False).size()
        lists = pairs.groupby("source_row_id", sort=False)["rule_id"].agg(list)
        frame["rule_match_count"] = frame["source_row_id"].map(counts).fillna(0).astype("Int64")
        frame["has_alert"] = frame["rule_match_count"].gt(0).astype("boolean")
        frame["alert_count"] = frame["has_alert"].astype("Int64")
        frame["alerts_evaluated"] = True
        frame["rule_ids"] = frame["source_row_id"].map(lists).map(lambda value: value if isinstance(value, list) else [])
    return frame


def _groups(frame: pd.DataFrame, pairs: pd.DataFrame | None, config: dict) -> pd.DataFrame:
    if frame.empty:
        result = pd.DataFrame(columns=GROUP_COLUMNS)
        for col in ("event_count", "alert_count", "rule_match_count"):
            result[col] = result[col].astype("Int64")
        for col in ("start_time", "end_time"):
            result[col] = pd.to_datetime(result[col]).astype("datetime64[ns]")
        return result
    grouped = frame.groupby("group_id", sort=False)
    result = grouped.agg(user=("User", "first"), agent=("Agent_name", "first"),
                         start_time=("Timestamp", "first"), end_time=("Timestamp", "last"),
                         event_count=("source_row_id", "size")).reset_index()
    source_lists = frame["source_row_id"].astype(object).groupby(frame["group_id"], sort=False).agg(list)
    result["source_row_ids"] = result["group_id"].map(source_lists)
    activities = frame[["group_id", "Activity"]].dropna(subset=["Activity"]).drop_duplicates()
    activity_lists = activities["Activity"].astype(object).groupby(activities["group_id"], sort=False).agg(list)
    result["activities"] = result["group_id"].map(activity_lists).map(lambda value: value if isinstance(value, list) else [])
    result["key"] = pd.DataFrame({"user": result["user"], "agent": result["agent"]}).to_dict("records")
    if pairs is None:
        result["alert_count"] = pd.Series(pd.NA, index=result.index, dtype="Int64")
        result["rule_match_count"] = pd.Series(pd.NA, index=result.index, dtype="Int64")
        result["rule_ids"] = [[] for _ in range(len(result))]
    else:
        links = frame[["source_row_id", "group_id"]].merge(pairs, on="source_row_id", how="inner", validate="one_to_many")
        counts = links.groupby("group_id", sort=False).agg(alert_count=("source_row_id", "nunique"), rule_match_count=("rule_id", "size"))
        unique_rules = links[["group_id", "rule_id"]].drop_duplicates().sort_values("rule_id")
        rule_lists = unique_rules["rule_id"].astype(object).groupby(unique_rules["group_id"], sort=False).agg(list)
        for col in ("alert_count", "rule_match_count"):
            result[col] = result["group_id"].map(counts[col]).fillna(0).astype("Int64")
        result["rule_ids"] = result["group_id"].map(rule_lists).map(lambda value: value if isinstance(value, list) else [])
    result["event_count"] = result["event_count"].astype("Int64")
    result = result.loc[result["event_count"].ge(config["min_events"]), list(GROUP_COLUMNS)]
    return result.sort_values(["start_time", "group_id"], kind="stable").reset_index(drop=True)


def correlate(
    logs: pd.DataFrame, alerts: list[dict] | pd.DataFrame | None = None, *,
    config: CorrelationConfig | None = None, as_of=None, report: dict | None = None,
) -> pd.DataFrame:
    """Return GROUP_COLUMNS; alert_count counts alert events, not rule matches.

    groups use fixed [bucket_start, bucket_end) and split when gap > max_gap.
    Defaults: 900s fixed window, 300s inactivity gap, min_events=1. None alerts
    means not_run (nullable counts); [] means detector completed with no alerts.
    Future-only appends preserve historical membership/group_id. For exact
    historical aggregate/timeline equality, use the same as_of tuple in both calls.
    Late insertion into earlier time requires rebuilding and is not append-only.
    """
    started = time.perf_counter()
    info = {"status": "running"}
    try:
        settings = _config(config)
        frame, info = _sessionize(logs, settings, as_of)
        pairs = _alert_pairs(alerts, logs)
        groups = _groups(frame, pairs, settings)
        returned = frame.loc[_identifier_isin(frame["group_id"], groups["group_id"]), "source_row_id"]
        info.update(status="success", groups_returned=len(groups),
                    rows_in_returned_groups=int(groups["event_count"].sum()),
                    rows_hidden_min_events=len(frame)-len(returned),
                    detector_state="not_run" if pairs is None else "success",
                    alert_events_excluded_from_grouping=None if pairs is None else int(pairs.loc[~_identifier_isin(pairs["source_row_id"], returned), "source_row_id"].nunique()))
        info["elapsed_seconds"] = round(time.perf_counter()-started, 6)
        groups.attrs["correlation_report"] = info.copy()
        return groups
    except (ValueError, TypeError) as error:
        info.update(status="error", error=str(error))
        raise
    finally:
        if report is not None:
            report.clear()
            report.update(info)


def get_timeline(
    logs: pd.DataFrame, group_id: str, alerts: list[dict] | pd.DataFrame | None = None, *,
    config: CorrelationConfig | None = None, as_of=None,
) -> pd.DataFrame:
    """Chronological source events plus has_alert/rule_ids; raw fields unchanged.

    For a captured historical group, pass its snapshot's as_of tuple. Does not
    expose Anomaly or replace missing identity/time. Unknown/filtered group raises
    ValueError instead of silently returning a different/empty group.
    """
    settings = _config(config)
    frame, info = _sessionize(logs, settings, as_of)
    if not isinstance(group_id, str) or not group_id:
        raise ValueError("group_id must be a nonempty string.")
    selected = frame.loc[frame["group_id"].eq(group_id)].copy()
    if selected.empty or len(selected) < settings["min_events"]:
        raise ValueError("group_id not found in the current snapshot/config: "+group_id)
    selected = _annotate(selected, _alert_pairs(alerts, logs))
    selected = selected.drop(columns=["_corr_bucket", "_corr_segment"]).reset_index(drop=True)
    selected.attrs["correlation_report"] = info
    return selected


def correlate_events(
    logs: pd.DataFrame, alerts: list[Alert], *, config: CorrelationConfig, as_of=None,
) -> list[Correlation]:
    """Compatibility adapter for the earlier scaffold; one visible snapshot/group.

    New integrations should use correlate/get_timeline. This is not a per-event
    sliding window: anchor is the last visible event in each fixed/gap group.
    """
    groups = correlate(logs, alerts, config=config, as_of=as_of)
    return [{"correlation_id": g["group_id"], "correlation_rule_id": "FIXED_GAP_SESSION_V1",
             "anchor_source_row_id": g["source_row_ids"][-1], "source_row_ids": g["source_row_ids"],
             "window_start": g["start_time"].isoformat(timespec="milliseconds"),
             "window_end": g["end_time"].isoformat(timespec="milliseconds"),
             "user": g["user"], "agent": g["agent"],
             "reason": "Grouped by User/Agent using a fixed window and inactivity gap, through the current snapshot only."}
            for g in groups.to_dict("records")]
