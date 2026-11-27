"""Typed CSV handoff for atomic alerts, merged v1.0 alerts and event groups.

Every CSV travels with its .schema.json sidecar. Lists/dicts are JSON cells;
null scalars use a noncolliding marker. Detection logic/config are unchanged.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pandas as pd

from detection.alert_aggregation import (
    MERGED_ALERT_COLUMNS, merged_alerts_to_dataframe,
    validate_atomic_alert, validate_merged_alert,
)
from detection.correlation import GROUP_COLUMNS
from detection.rule_engine import ALERT_COLUMNS, alerts_to_dataframe

FORMAT = "spedia.shared_outputs.v1"
LAYOUTS = {
    "atomic_alerts": (ALERT_COLUMNS, ("evidence",)),
    "merged_alerts": (MERGED_ALERT_COLUMNS, ("rule_ids", "rule_matches")),
    "event_groups": (GROUP_COLUMNS, ("key", "activities", "rule_ids", "source_row_ids")),
}


def _sidecar(path: Path) -> Path:
    return path.with_suffix(".schema.json")


def _check_atomic(alerts: list[dict]) -> None:
    for alert in alerts:
        validate_atomic_alert(alert)
    if len({a["alert_id"] for a in alerts}) != len(alerts):
        raise ValueError("Atomic output contains duplicate alert_id values; handle repeat deliveries before exporting.")


def _check_merged(alerts: list[dict]) -> None:
    for alert in alerts:
        validate_merged_alert(alert)
    if len({a["source_row_id"] for a in alerts}) != len(alerts):
        raise ValueError("Merged output requires a unique row per source_row_id.")


def _check_groups(groups: pd.DataFrame) -> None:
    if not isinstance(groups, pd.DataFrame) or groups.columns.tolist() != list(GROUP_COLUMNS):
        raise ValueError("Event groups require exactly the 12 correlate() columns.")
    if groups.empty:
        return
    for column in ("group_id", "user", "agent"):
        if groups[column].isna().any() or not groups[column].map(lambda x: isinstance(x, str) and bool(x.strip())).astype(bool).all():
            raise ValueError(f"Invalid group {column}.")
    if groups.group_id.duplicated().any():
        raise ValueError("Duplicate group_id.")
    for column in ("start_time", "end_time"):
        if (not pd.api.types.is_datetime64_any_dtype(groups[column]) or groups[column].dt.tz is not None
                or groups[column].isna().any()):
            raise ValueError(f"Group {column} requires valid timezone-naive datetime.")
    if groups.start_time.gt(groups.end_time).any():
        raise ValueError("Group start_time exceeds end_time.")
    for column in ("event_count", "alert_count", "rule_match_count"):
        if not pd.api.types.is_integer_dtype(groups[column].dtype):
            raise ValueError(f"Group {column} requires nullable integers.")
    if groups.event_count.isna().any() or groups.event_count.le(0).any():
        raise ValueError("event_count must be positive.")
    for column in ("activities", "rule_ids", "source_row_ids"):
        if not groups[column].map(lambda x: isinstance(x, list) and all(isinstance(v, str) and bool(v) for v in x) and len(x) == len(set(x))).astype(bool).all():
            raise ValueError(f"Group {column} requires a list of unique strings.")
    if not groups.source_row_ids.str.len().eq(groups.event_count).all():
        raise ValueError("event_count does not equal the number of source_row_ids.")
    if groups.source_row_ids.explode().duplicated().any():
        raise ValueError("A source_row_id appears in multiple groups.")
    for row in groups[["group_id", "key", "user", "agent", "rule_ids", "source_row_ids"]].to_dict("records"):
        if row["key"] != {"user": row["user"], "agent": row["agent"]}:
            raise ValueError("Group key does not match user/agent.")
        if row["rule_ids"] != sorted(row["rule_ids"]):
            raise ValueError("Group rule_ids must be sorted.")
        if not row["group_id"].startswith("corr:v1:") or not row["group_id"].endswith(":"+row["source_row_ids"][0]):
            raise ValueError("group_id does not match the first event in the group.")
    if groups.alert_count.isna().any() or groups.rule_match_count.isna().any():
        if not (groups.alert_count.isna().all() and groups.rule_match_count.isna().all() and groups.rule_ids.str.len().eq(0).all()):
            raise ValueError("Partially missing alert counts; distinguish not_run from zero alerts.")
    elif (groups.alert_count.lt(0).any() or groups.alert_count.gt(groups.event_count).any()
          or groups.rule_match_count.lt(groups.alert_count).any()
          or groups.rule_ids.str.len().gt(groups.rule_match_count).any()
          or (groups.alert_count.eq(0) != groups.rule_match_count.eq(0)).any()
          or (groups.alert_count.eq(0) != groups.rule_ids.str.len().eq(0)).any()):
        raise ValueError("Group alert_count/rule_match_count/rule_ids are inconsistent.")


def _write(frame: pd.DataFrame, path: str | Path, kind: str, provenance: dict | None) -> dict:
    path = Path(path)
    if path.suffix.casefold() != ".csv":
        raise ValueError("Output requires a .csv extension.")
    columns, json_columns = LAYOUTS[kind]
    if frame.columns.tolist() != list(columns):
        raise ValueError("Incorrect output columns/order.")
    if path.exists():
        if not _sidecar(path).exists():
            raise ValueError("The target exists without a valid sidecar; refusing to overwrite an unidentified file.")
        previous = json.loads(_sidecar(path).read_text(encoding="utf-8"))
        if previous.get("format_version") != FORMAT or previous.get("kind") != kind:
            raise ValueError("Refusing to overwrite an artifact of a different kind/version.")
    attrs = json.loads(json.dumps(copy.deepcopy(frame.attrs), ensure_ascii=False, allow_nan=False))
    origin = json.loads(json.dumps(copy.deepcopy(provenance or {}), ensure_ascii=False, allow_nan=False))
    dtypes = {c: str(frame[c].dtype) for c in columns}
    wire = frame.copy(deep=True)
    wire.attrs = {}
    for column in json_columns:
        wire[column] = wire[column].map(lambda x: json.dumps(x, ensure_ascii=False, allow_nan=False))
    marker, counter = "__SPEDIA_NULL__", 0
    text_columns = [c for c in columns if not pd.api.types.is_datetime64_any_dtype(wire[c]) and not pd.api.types.is_integer_dtype(wire[c])]
    while any(wire[c].eq(marker).fillna(False).any() for c in text_columns):
        counter += 1
        marker = f"__SPEDIA_NULL__{counter}"
    path.parent.mkdir(parents=True, exist_ok=True)
    wire.to_csv(path, index=False, encoding="utf-8-sig", na_rep=marker,
                date_format="%Y-%m-%d %H:%M:%S.%f", lineterminator="\n")
    metadata = {"format_version": FORMAT, "kind": kind, "schema_version": "1.0" if kind != "event_groups" else "corr.v1",
                "encoding": "utf-8-sig", "row_count": len(frame), "columns": list(columns),
                "json_columns": list(json_columns), "dtypes": dtypes, "null_marker": marker,
                "csv_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "attrs": attrs, "provenance": origin}
    _sidecar(path).write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    return metadata


def _read(path: str | Path, kind: str) -> pd.DataFrame:
    path = Path(path)
    if not _sidecar(path).is_file():
        raise FileNotFoundError(f"Missing sidecar {_sidecar(path)}; transfer both CSV and .schema.json.")
    metadata = json.loads(_sidecar(path).read_text(encoding="utf-8"))
    columns, json_columns = LAYOUTS[kind]
    if (metadata.get("format_version") != FORMAT or metadata.get("kind") != kind
            or metadata.get("columns") != list(columns) or metadata.get("json_columns") != list(json_columns)):
        raise ValueError("Incorrect shared CSV kind/schema.")
    expected_version = "corr.v1" if kind == "event_groups" else "1.0"
    if metadata.get("schema_version") != expected_version:
        raise ValueError("Unsupported artifact version.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["csv_sha256"]:
        raise ValueError("Checksum of CSV does not match the sidecar.")
    frame = pd.read_csv(path, encoding=metadata["encoding"], dtype="string", keep_default_na=False,
                        na_values=[metadata["null_marker"]], skip_blank_lines=False)
    if frame.columns.tolist() != list(columns) or len(frame) != metadata["row_count"]:
        raise ValueError("CSV row/column counts do not match the sidecar.")
    for column in columns:
        values, dtype = frame[column], metadata["dtypes"][column]
        if column in json_columns:
            if values.isna().any():
                raise ValueError(f"JSON column {column} must not contain missing values.")
            frame[column] = values.map(json.loads).astype(object)
        elif kind == "event_groups" and column in {"start_time", "end_time"}:
            if dtype not in {"datetime64[ns]", "datetime64[us]", "datetime64[ms]", "datetime64[s]"}:
                raise ValueError("Incorrect group datetime dtype.")
            frame[column] = pd.to_datetime(values, format="%Y-%m-%d %H:%M:%S.%f", errors="raise").astype(dtype)
        elif kind == "event_groups" and column in {"event_count", "alert_count", "rule_match_count"}:
            if dtype not in {"Int64", "int64"}:
                raise ValueError("Incorrect group count dtype.")
            frame[column] = pd.to_numeric(values, errors="raise").astype(dtype)
        else:
            if dtype not in {"string", "str", "object"}:
                raise ValueError("Incorrect output text dtype.")
            frame[column] = values.astype(dtype)
    frame.attrs = copy.deepcopy(metadata["attrs"])
    return frame


def _alert_records(frame: pd.DataFrame) -> list[dict]:
    return frame.astype(object).where(frame.notna(), None).to_dict("records")


def save_atomic_alerts(alerts: list[dict], path: str | Path = "data/alerts_atomic.csv", *, provenance: dict | None = None) -> dict:
    _check_atomic(alerts)
    return _write(alerts_to_dataframe(alerts), path, "atomic_alerts", provenance)


def read_atomic_alerts(path: str | Path = "data/alerts_atomic.csv") -> list[dict]:
    alerts = _alert_records(_read(path, "atomic_alerts"))
    _check_atomic(alerts)
    return alerts


def save_alerts(alerts: list[dict], path: str | Path = "data/alerts.csv", *, provenance: dict | None = None) -> dict:
    """Canonical alerts.csv is Task 5 merged v1.0, not an overwritten atomic table."""
    _check_merged(alerts)
    return _write(merged_alerts_to_dataframe(alerts), path, "merged_alerts", provenance)


def read_alerts(path: str | Path = "data/alerts.csv") -> list[dict]:
    alerts = _alert_records(_read(path, "merged_alerts"))
    _check_merged(alerts)
    return alerts


def save_event_groups(groups: pd.DataFrame, path: str | Path = "data/event_groups.csv", *, provenance: dict | None = None) -> dict:
    _check_groups(groups)
    return _write(groups, path, "event_groups", provenance)


def read_event_groups(path: str | Path = "data/event_groups.csv") -> pd.DataFrame:
    groups = _read(path, "event_groups")
    _check_groups(groups)
    return groups
