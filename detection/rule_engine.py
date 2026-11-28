"""Dataset-grounded, explainable rules for SPEDIA event logs."""
from __future__ import annotations

import ipaddress
import re
from collections import deque
from urllib.parse import urlsplit

import pandas as pd

from preprocessing.source_ids import validate_source_row_ids


RULE_SEVERITIES = {
    "CMD_NMAP": "MEDIUM",
    "CMD_JOHN": "MEDIUM",
    "CMD_MSFCONSOLE": "MEDIUM",
    "FILE_CONFIG_CHANGE": "MEDIUM",
    "HTTP_IP_HOST": "LOW",
    "AUTH_FAILURE_WINDOW": "MEDIUM",
}
COMMAND_RULES = {
    "nmap": "CMD_NMAP",
    "john": "CMD_JOHN",
    "msfconsole": "CMD_MSFCONSOLE",
}
CONFIG_PATH = re.compile(
    r"^/etc/(?:apache2/|ssh/|vsftpd\.conf$|passwd$|shadow$|sudoers(?:$|\.d/))"
)
AUTH_CONTEXT = re.compile(
    r"authentication failure|user login failed|failed password|"
    r"failed publickey|login failed|login failure|multiple failed logins",
    re.IGNORECASE,
)
CHANGED_ATTRIBUTES = re.compile(
    r"Changed attributes:\s*([A-Za-z0-9_,]+)", re.IGNORECASE
)
AUTH_FAILURE_ACTIONS = {"login failed", "multiple failed logins"}
AUTH_WINDOW = pd.Timedelta(seconds=300)
ALERT_COLUMNS = [
    "timestamp",
    "user",
    "agent",
    "activity",
    "rule_id",
    "reason",
    "severity",
    "source_row_id",
    "alert_id",
    "evidence",
]


def _make_alert(row: pd.Series, rule_id: str, reason: str, evidence: dict) -> dict:
    source_row_id = str(row["source_row_id"])
    return {
        "timestamp": row["Timestamp"],
        "user": row.get("User", pd.NA),
        "agent": row.get("Agent_name", pd.NA),
        "activity": row.get("Activity", pd.NA),
        "rule_id": rule_id,
        "reason": reason,
        "severity": RULE_SEVERITIES[rule_id],
        "source_row_id": source_row_id,
        "alert_id": f"{source_row_id}:{rule_id}",
        "evidence": evidence,
    }


def _is_http_ip_host(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return False
        ipaddress.ip_address(parsed.hostname)
        return True
    except ValueError:
        return False


def run_rules(events: pd.DataFrame) -> pd.DataFrame:
    """Run enabled rules and return one traceable row per event/rule match."""
    required = {
        "source_row_id",
        "Timestamp",
        "User",
        "Agent_name",
        "Activity",
        "Action",
        "Command",
        "Path",
        "Full_log",
        "Description",
        "Url",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(
            "Rule Engine thiếu cột bắt buộc: " + ", ".join(sorted(missing))
        )
    events = events.copy()
    events["source_row_id"] = validate_source_row_ids(
        events,
        component="Rule Engine",
    )

    rule_columns = [
        "source_row_id",
        "Timestamp",
        "User",
        "Agent_name",
        "Activity",
        "Action",
        "Command",
        "Path",
        "Full_log",
        "Description",
        "Url",
    ]
    if "record_index" in events.columns:
        rule_columns.append("record_index")
    ordered = events[rule_columns].sort_values(
        ["Timestamp", "record_index"]
        if "record_index" in events.columns
        else ["Timestamp"],
        kind="stable",
        na_position="last",
    ).reset_index(drop=True)
    alerts = []
    action = ordered["Action"].astype("string").fillna("").str.strip().str.casefold()
    valid_timestamp = ordered["Timestamp"].notna()
    command = ordered["Command"].astype("string").fillna("").str.strip()
    basename = command.str.rstrip("/").str.rsplit("/", n=1).str[-1]
    command_mask = (
        valid_timestamp
        & action.eq("command executed")
        & basename.isin(COMMAND_RULES)
    )
    for _, row in ordered.loc[command_mask].iterrows():
        executable = str(basename.iloc[row.name])
        alerts.append(
            _make_alert(
                row,
                COMMAND_RULES[executable],
                f"Command basename is {executable!r} in a command-executed event.",
                {"matched_field": "Command", "matched_value": row["Command"]},
            )
        )

    path = ordered["Path"].astype("string").fillna("").str.strip()
    file_mask = (
        valid_timestamp
        & action.isin({"file modified", "file added", "file deleted"})
        & path.str.match(CONFIG_PATH, na=False)
    )
    file_rows = ordered.loc[file_mask]
    if not file_rows.empty:
        file_actions = action.loc[file_rows.index]
        raw_logs = file_rows["Full_log"].astype("string").fillna("")
        attributes = raw_logs.str.extract(CHANGED_ATTRIBUTES, expand=False)
        metadata_only = (
            attributes.fillna("").map(
                lambda value: bool(value)
                and {item.casefold() for item in value.split(",")}.issubset(
                    {"mtime", "ctime"}
                )
            )
            & raw_logs.str.contains(r"\bOld\b", case=False, na=False)
        )
        include_rows = ~(file_actions.eq("file modified") & metadata_only)
        for _, row in file_rows.loc[include_rows].iterrows():
            path_value = str(path.iloc[row.name])
            action_value = str(action.iloc[row.name])
            alerts.append(
                _make_alert(
                    row,
                    "FILE_CONFIG_CHANGE",
                    f"Configured system path changed: {path_value!r} ({action_value}).",
                    {
                        "matched_field": "Path",
                        "matched_value": row["Path"],
                        "Action": action_value,
                        "Full_log": row["Full_log"],
                        "Description": row["Description"],
                    },
                )
            )

    url = ordered["Url"].astype("string").fillna("").str.strip()
    http_mask = (
        valid_timestamp
        & action.isin({"url accedida", "url accessed"})
        & url.ne("")
    )
    for _, row in ordered.loc[http_mask].iterrows():
        url_value = str(url.iloc[row.name])
        if _is_http_ip_host(url_value):
            alerts.append(
                _make_alert(
                    row,
                    "HTTP_IP_HOST",
                    f"HTTP(S) URL uses an IP-literal host: {url_value!r}.",
                    {"matched_field": "Url", "matched_value": row["Url"]},
                )
            )

    auth_mask = action.isin(AUTH_FAILURE_ACTIONS)
    for column in ("Action", "Description", "Full_log"):
        auth_values = ordered[column].astype("string").fillna("")
        auth_mask |= auth_values.str.contains(AUTH_CONTEXT, na=False)
    auth_frame = ordered.loc[
        auth_mask
        & ordered["Timestamp"].notna()
        & ordered["User"].astype("string").fillna("").str.strip().ne("")
        & ordered["Agent_name"].astype("string").fillna("").str.strip().ne("")
    ]
    if not auth_frame.empty:
        auth_frame = auth_frame.sort_values(
            ["User", "Agent_name", "Timestamp", "record_index"]
            if "record_index" in auth_frame.columns
            else ["User", "Agent_name", "Timestamp"],
            kind="stable",
        )
        for _, group in auth_frame.groupby(
            ["User", "Agent_name"], sort=False, dropna=True
        ):
            window = deque()
            for row in group.itertuples(index=False):
                row = pd.Series(row._asdict())
                timestamp = row["Timestamp"]
                cutoff = timestamp - AUTH_WINDOW
                while window and window[0] < cutoff:
                    window.popleft()
                window.append(timestamp)
                if len(window) >= 3:
                    alerts.append(
                        _make_alert(
                            row,
                            "AUTH_FAILURE_WINDOW",
                            "At least 3 explicit authentication failures for this user/agent within 300 seconds.",
                            {
                                "window_seconds": 300,
                                "failure_count": len(window),
                                "window_start": window[0],
                                "window_end": timestamp,
                            },
                        )
                    )

    result = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    if result.empty:
        return result
    return result.sort_values(
        ["timestamp", "source_row_id", "rule_id"], kind="stable"
    ).reset_index(drop=True)
