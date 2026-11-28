"""Configured, explainable prototype alerts with causal authentication windows.

Predicates use vectorized pandas operations. Only matching alerts are serialized
in Python; URL parsing is cached per distinct URL. Anomaly/Level never enter the
working frame. Severity means prototype triage priority, not verified impact.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
import string
import time
from datetime import timedelta
from pathlib import Path

import pandas as pd

from preprocessing.contracts import Alert, RuleConfig

DEFAULT_CONFIG = Path(__file__).with_name("rules.json")
ALERT_COLUMNS = (
    "timestamp", "user", "agent", "activity", "rule_id", "reason", "severity",
    "source_row_id", "alert_id", "evidence", "severity_reason",
)
CORE_COLUMNS = ("Timestamp", "User", "Agent_name", "Activity", "Action", "source_row_id", "record_index")
PARAMETERS = {
    "command_in": {"commands", "actions"},
    "file_path_change": {"path_regex", "actions"},
    "http_ip_host": {"actions"},
    "auth_failure_window": {"threshold", "window_seconds", "failure_actions", "failure_regex"},
}
OPTIONAL_PARAMETERS = {"command_in": {"case_sensitive"}, "file_path_change": {"exclude_modified_raw_regex"}}
DEPENDENCIES = {"command_in": ["Command"], "file_path_change": ["Path"], "http_ip_host": ["Url"], "auth_failure_window": []}
REASON_FIELDS = {"matched_field", "matched_value", "action", "host", "count", "threshold", "window_seconds", "window_start", "window_end", "user", "agent", "rule_id", "source_row_id"}


def load_rule_config(path: str | Path | None = None) -> RuleConfig:
    """Read JSON without eval, validate schema and all enabled/disabled rules."""
    with Path(path or DEFAULT_CONFIG).open(encoding="utf-8-sig") as stream:
        config = json.load(stream)
    _validate_config(config)
    return config


def _validate_config(config: dict) -> None:
    if not isinstance(config, dict) or config.get("schema_version") != "spedia.rules.v1" or not isinstance(config.get("rules"), list):
        raise ValueError("Config requires schema_version=spedia.rules.v1 and rules as a list.")
    ids = set()
    for rule in config["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Each rule must be an object.")
        rid = rule.get("rule_id")
        if not isinstance(rid, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", rid) or rid in ids:
            raise ValueError(f"Invalid or duplicate rule_id: {rid!r}.")
        ids.add(rid)
        kind = rule.get("condition")
        if not isinstance(kind, str) or kind not in PARAMETERS:
            raise ValueError(f"{rid}: unsupported condition: {kind!r}.")
        params = rule.get("params")
        if (not isinstance(params, dict) or not PARAMETERS[kind].issubset(params)
                or set(params) - PARAMETERS[kind] - OPTIONAL_PARAMETERS.get(kind, set())):
            raise ValueError(f"{rid}: params must contain the expected keys {sorted(PARAMETERS[kind])}.")
        if "case_sensitive" in params and type(params["case_sensitive"]) is not bool:
            raise ValueError(f"{rid}: case_sensitive must be boolean.")
        if type(rule.get("enabled")) is not bool or not isinstance(rule.get("base_severity"), str) or rule["base_severity"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"{rid}: enabled must be boolean; base_severity must be LOW/MEDIUM/HIGH/CRITICAL.")
        for key in ("reason_template", "severity_reason", "rationale"):
            if not isinstance(rule.get(key), str) or not rule[key].strip():
                raise ValueError(f"{rid}: missing {key}.")
        reason_fields = set()
        for _, field, spec, conversion in string.Formatter().parse(rule["reason_template"]):
            if field is not None and (field not in REASON_FIELDS or spec or conversion not in (None, "s", "r", "a")):
                raise ValueError(f"{rid}: invalid reason placeholder: {field!r}.")
            if field is not None:
                reason_fields.add(field)
        if not {"matched_field", "matched_value"}.issubset(reason_fields):
            raise ValueError(f"{rid}: reason_template must include matched_field and matched_value.")
        for key in ("commands", "actions", "failure_actions"):
            if key in params and (not isinstance(params[key], list) or not params[key]
                                  or any(not isinstance(x, str) or not x.strip() for x in params[key])):
                raise ValueError(f"{rid}: {key} must be a nonempty list of nonempty strings.")
        for key in ("path_regex", "failure_regex", "exclude_modified_raw_regex"):
            if key in params:
                if not isinstance(params[key], str) or not params[key]:
                    raise ValueError(f"{rid}: {key} must not be empty.")
                try:
                    re.compile(params[key])
                except re.error as error:
                    raise ValueError(f"{rid}: invalid {key}: {error}") from error
        for key in ("threshold", "window_seconds"):
            if key in params and (type(params[key]) is not int or params[key] <= 0):
                raise ValueError(f"{rid}: {key} must be a positive integer.")
        if "window_seconds" in params:
            try:
                pd.Timedelta(seconds=params["window_seconds"])
            except (ValueError, OverflowError) as error:
                raise ValueError(f"{rid}: window_seconds is outside the Timedelta range.") from error
    if "enabled_rule_ids" in config:
        selected = config["enabled_rule_ids"]
        if not isinstance(selected, list) or any(not isinstance(x, str) for x in selected) or len(selected) != len(set(selected)) or set(selected) - ids:
            raise ValueError("enabled_rule_ids must be a list of unique, defined rule IDs.")


def _resolve_config(config: RuleConfig | str | Path | None) -> RuleConfig:
    if config is None or isinstance(config, (str, Path)):
        return load_rule_config(config)
    if isinstance(config, dict) and set(config) == {"enabled_rule_ids"}:
        result = load_rule_config()
        result["enabled_rule_ids"] = copy.deepcopy(config["enabled_rule_ids"])
    else:
        result = copy.deepcopy(config)
    _validate_config(result)
    return result


def _strings(frame: pd.DataFrame, column: str) -> pd.Series:
    return frame[column].astype("string")


def _dependencies(rule: dict) -> list[str]:
    columns = list(DEPENDENCIES[rule["condition"]])
    if rule["condition"] == "file_path_change" and "exclude_modified_raw_regex" in rule["params"]:
        columns.append("Full_log")
    return columns


def _ip_hostname(url: str) -> str | None:
    # Parse each distinct URL once; only absolute HTTP(S) URLs qualify.
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return None
        ipaddress.ip_address(parsed.hostname)
        # Also reject malformed ports rather than classifying a broken URL.
        parsed.port
        return parsed.hostname
    except ValueError:
        return None


def _text(value) -> str | None:
    return None if pd.isna(value) else str(value)


def detect_rules(
    logs: pd.DataFrame, *, config: RuleConfig | str | Path | None = None,
    report: dict | None = None,
) -> list[Alert]:
    """Detect using normalized events; return contract alerts, without Anomaly.

    Missing required columns (including active-rule fields) raise ValueError.
    Missing cell values and invalid times are skipped with explicit run counts.
    Optional report is filled on success/error; input frame/config stay untouched.
    Auth windows group by (User, Agent_name), are closed at both boundaries, and
    count only observed failure records up to the anchor in Timestamp/record_index
    order. Missing users are never pooled. No labels calibrate rules or priority.
    """
    started = time.perf_counter()
    run = {"status": "running", "rows_input": len(logs) if isinstance(logs, pd.DataFrame) else 0,
           "rules": [], "missing_columns": [], "alerts_count": 0}
    try:
        resolved = _resolve_config(config)
        selected = resolved.get("enabled_rule_ids")
        active = [r for r in resolved["rules"] if (r["rule_id"] in selected if selected is not None else r["enabled"])]
        run["disabled_rule_ids"] = [r["rule_id"] for r in resolved["rules"] if r not in active]
        if not isinstance(logs, pd.DataFrame):
            raise TypeError("Rule Engine requires a pandas DataFrame from the normalizer.")
        if not logs.columns.is_unique:
            raise ValueError("Rule Engine: duplicate input column names.")
        required = set(CORE_COLUMNS)
        for rule in active:
            required.update(_dependencies(rule))
        missing = sorted(required - set(logs.columns))
        if missing:
            run["missing_columns"] = missing
            details = [r["rule_id"]+": "+", ".join(c for c in _dependencies(r) if c in missing)
                       for r in active if any(c in missing for c in _dependencies(r))]
            raise ValueError("Rule Engine is missing columns: " + ", ".join(missing) + (" ("+"; ".join(details)+")" if details else ""))
        if not pd.api.types.is_datetime64_any_dtype(logs["Timestamp"]) or logs["Timestamp"].dt.tz is not None:
            raise ValueError("Timestamp must be timezone-naive datetime from the normalizer.")
        indices = logs["record_index"]
        if (not pd.api.types.is_integer_dtype(indices.dtype) or pd.api.types.is_bool_dtype(indices.dtype)
                or indices.isna().any() or indices.lt(0).any() or indices.duplicated().any()):
            raise ValueError("record_index must contain unique, nonmissing, nonnegative integers within the file.")
        ids = logs["source_row_id"]
        if ids.isna().any() or ids.duplicated().any() or not ids.map(lambda x: isinstance(x, str) and bool(x.strip())).astype(bool).all():
            raise ValueError("source_row_id must contain unique, nonempty, nonmissing strings.")
        extras = ("Command", "Path", "Filename", "Url", "Description", "Full_log", "Content", "Action_raw", "User_raw", "Agent_name_raw", "Activity_raw", "Timestamp_raw", "invalid_timestamp")
        columns = [*CORE_COLUMNS, *(c for c in extras if c in logs)]
        frame = logs.loc[:, columns].copy()
        frame.attrs = {}  # Do not copy large loader attrs into per-rule intermediates.
        frame = frame.sort_values(["Timestamp", "record_index"], kind="stable", na_position="last").reset_index(drop=True)
        valid_time = frame["Timestamp"].notna()
        if "invalid_timestamp" in frame:
            if not pd.api.types.is_bool_dtype(frame["invalid_timestamp"]):
                raise ValueError("invalid_timestamp must be a boolean column from the normalizer.")
            valid_time &= ~frame["invalid_timestamp"].fillna(True)
        valid_context = pd.Series(True, index=frame.index)
        for column in ("Agent_name", "Activity"):
            valid_context &= _strings(frame, column).str.strip().ne("").fillna(False)
        eligible = valid_time & valid_context
        run["rows_invalid_time"] = int((~valid_time).sum())
        run["rows_missing_context"] = int((~valid_context).sum())
        actions = _strings(frame, "Action").str.strip().str.casefold()
        alerts: list[Alert] = []
        for rule in active:
            rule_started = time.perf_counter()
            kind, params = rule["condition"], rule["params"]
            info = {"rule_id": rule["rule_id"], "condition": kind, "status": "success", "matches": 0}
            matches = eligible.copy()
            field = pd.Series("", index=frame.index, dtype="string")
            value = pd.Series("", index=frame.index, dtype="string")
            hosts = pd.Series(pd.NA, index=frame.index, dtype="string")
            counts = pd.Series(0, index=frame.index, dtype="int64")
            if kind in {"command_in", "file_path_change", "http_ip_host"}:
                matches &= actions.isin([x.strip().casefold() for x in params["actions"]])
                source = {"command_in": "Command", "file_path_change": "Path", "http_ip_host": "Url"}[kind]
                text = _strings(frame, source)
                present = text.str.strip().ne("").fillna(False)
                info["rows_missing_fields"] = int((matches & ~present).sum())
                matches &= present
                field[:] = source
                value = text
                if kind == "command_in":
                    command = text.str.strip().str.replace("\\", "/", regex=False).str.rsplit("/", n=1).str[-1]
                    commands = [x.strip() for x in params["commands"]]
                    if not params.get("case_sensitive", True):
                        command = command.str.casefold()
                        commands = [x.casefold() for x in commands]
                    matches &= command.isin(commands)
                elif kind == "file_path_change":
                    matches &= text.str.contains(params["path_regex"], regex=True, na=False)
                    if "exclude_modified_raw_regex" in params:
                        metadata_only = actions.eq("file modified") & _strings(frame, "Full_log").str.contains(
                            params["exclude_modified_raw_regex"], case=False, regex=True, na=False
                        )
                        info["rows_excluded_metadata_only"] = int((matches & metadata_only).sum())
                        matches &= ~metadata_only
                else:
                    distinct = text.loc[matches].dropna().unique()
                    mapping = {url: _ip_hostname(url) for url in distinct}
                    hosts = text.map(mapping).astype("string")
                    matches &= hosts.notna()
            else:
                failure = (actions.isin([x.strip().casefold() for x in params["failure_actions"]])
                           | actions.str.contains(params["failure_regex"], case=False, regex=True, na=False))
                field.loc[failure] = "Action"
                value.loc[failure] = _strings(frame, "Action").loc[failure]
                info["missing_optional_signal_columns"] = [c for c in ("Description", "Full_log") if c not in frame]
                for source in ("Description", "Full_log"):
                    if source in frame:
                        signal = _strings(frame, source).str.contains(params["failure_regex"], case=False, regex=True, na=False)
                        newly_matched = signal & ~failure
                        field.loc[newly_matched] = source
                        value.loc[newly_matched] = _strings(frame, source).loc[newly_matched]
                        failure |= signal
                users_present = _strings(frame, "User").str.strip().ne("").fillna(False)
                info["explicit_failure_rows"] = int(failure.sum())
                info["failure_rows_missing_user"] = int((failure & ~users_present).sum())
                info["failure_rows_invalid_time"] = int((failure & ~valid_time).sum())
                usable = eligible & failure & users_present
                failures = frame.loc[usable, ["Timestamp", "User", "Agent_name"]].copy()
                if not failures.empty:
                    failures["_failure"] = 1.0
                    rolled = failures.groupby(["User", "Agent_name"], sort=False).rolling(
                        pd.Timedelta(seconds=params["window_seconds"]), on="Timestamp", closed="both", min_periods=1
                    ).sum()["_failure"].reset_index(level=[0, 1], drop=True)
                    counts.loc[failures.index] = rolled.reindex(failures.index).astype("int64")
                matches = usable & counts.ge(params["threshold"])
                info["threshold"] = params["threshold"]
                info["window_seconds"] = params["window_seconds"]
            matched = frame.loc[matches]
            for index, row in zip(matched.index, matched.to_dict("records")):
                timestamp = row["Timestamp"].isoformat(timespec="milliseconds")
                context = {
                    "rule_id": rule["rule_id"], "source_row_id": row["source_row_id"],
                    "user": _text(row["User"]), "agent": _text(row["Agent_name"]),
                    "action": _text(row["Action"]), "matched_field": field.at[index],
                    "matched_value": _text(value.at[index]), "host": _text(hosts.at[index]),
                    "count": int(counts.at[index]), "threshold": params.get("threshold", 0),
                    "window_seconds": params.get("window_seconds", 0), "window_end": timestamp,
                    "window_start": (row["Timestamp"].to_pydatetime() - timedelta(seconds=params.get("window_seconds", 0))).isoformat(timespec="milliseconds"),
                }
                evidence = {"matched_field": context["matched_field"], "matched_value": context["matched_value"], "Action": context["action"]}
                for column in ("Full_log", "Description", "Content", "Action_raw", "User_raw", "Agent_name_raw", "Activity_raw", "Timestamp_raw"):
                    if column in row:
                        evidence[column] = _text(row[column])
                if kind == "http_ip_host":
                    evidence["hostname"] = context["host"]
                if kind == "auth_failure_window":
                    for key in ("count", "threshold", "window_seconds", "window_start", "window_end"):
                        evidence[key] = str(context[key])
                alerts.append({
                    "alert_id": row["source_row_id"]+":"+rule["rule_id"],
                    "source_row_id": row["source_row_id"], "timestamp": timestamp,
                    "user": context["user"], "agent": context["agent"], "activity": _text(row["Activity"]),
                    "rule_id": rule["rule_id"], "reason": rule["reason_template"].format_map(context),
                    "evidence": evidence, "severity": rule["base_severity"],
                    "severity_reason": rule["severity_reason"],
                })
            info["matches"] = len(matched)
            info["elapsed_seconds"] = round(time.perf_counter()-rule_started, 6)
            run["rules"].append(info)
        # Serialization ordering does not participate in rule/window decisions.
        alerts.sort(key=lambda a: (a["timestamp"], a["source_row_id"], a["rule_id"]))
        run["alerts_count"] = len(alerts)
        run["status"] = "success"
        return alerts
    except (ValueError, TypeError, OSError) as error:
        run["status"] = "error"
        run["error"] = str(error)
        raise
    finally:
        run["elapsed_seconds"] = round(time.perf_counter()-started, 6)
        if report is not None:
            report.clear()
            report.update(run)


def alerts_to_dataframe(alerts: list[Alert]) -> pd.DataFrame:
    """Stable contract columns even for zero alerts; keep ISO timestamp strings."""
    frame = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    for column in ALERT_COLUMNS:
        if column != "evidence":
            frame[column] = frame[column].astype("string")
    return frame
