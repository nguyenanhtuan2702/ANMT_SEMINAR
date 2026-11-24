"""Reproducible, read-only SPEDIA survey using Python's standard library.

Run: python -m preprocessing.profile_dataset --input dataset_log/logs_SPEDIA_annotated_en.csv
Outputs are survey evidence, NOT detector results. Anomaly is never read by
candidate predicates or login scanning. The source file is never rewritten.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import platform
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from preprocessing.contracts import REQUIRED_COLUMNS

FREQUENCY_COLUMNS = ("Activity", "Action", "Decoder_name", "Command", "Url", "Path", "Filename")
SCAN_COLUMNS = ("Action", "Description", "Full_log", "Content")
LOGIN_PATTERN = re.compile(
    r"\b(?:login|logon|logoff|logout|authentication|pam_unix|sshd|fail(?:ed|ure|ures)?|denied|invalid)\b",
    re.IGNORECASE,
)
# Deliberately stricter than the exploratory keyword scan. 'invalid' alone is
# not sufficient. A sudo PAM failure is an auth failure, not proof of SSH failure.
AUTH_FAILURE_PATTERN = re.compile(
    r"\b(?:authentication failure|user login failed|failed (?:password|publickey)|"
    r"login (?:failed|failure)|multiple failed logins)\b", re.IGNORECASE,
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$")
NUMERIC_COLUMNS = {"Attachments", "Size", "Size_before", "Size_after", "Level", "Anomaly"}
SCHEMA_NOTES = {
    "id": "Source identifier; validate duplicates, do not use as internal row key",
    "Agent_name": "Source context; naming may disclose data-generation source",
    "User": "Nullable identity; preserve spelling, no automatic alias merging",
    "Timestamp": "Source text; validate YYYY-MM-DD HH:MM:SS.mmm; timezone absent",
    "Decoder_name": "Source decoder, not a detection outcome",
    "Description": "Raw text: preserve original value",
    "Full_log": "Raw text: preserve original value",
    "Content": "Raw text: preserve original value; prose keywords are not auth evidence",
    "Url": "HTTP context; frequency/IP host alone does not prove maliciousness",
    "To": "Email recipient list; preserve source separators",
    "Cc": "Optional email copy recipients; missing may be expected",
    "Bcc": "Optional email blind-copy recipients; missing may be expected",
    "From": "Email sender; differs from system User",
    "Attachments": "Numeric lexical form; nullable attachment count",
    "Size": "Nullable source size; do not fill missing with zero",
    "Size_before": "Nullable source size; negative values require investigation",
    "Size_after": "Nullable source size; absence is not size zero",
    "Filename": "File name; may be populated separately from Path",
    "Path": "File path; preserve raw case in source",
    "Command": "Command name may omit arguments; missing does not imply benign",
    "Level": "Source risk/alert level; NOT prototype severity",
    "Activity": "Event category only; never an attack verdict",
    "Action": "Source action; inspect explicit failure semantics",
    "Anomaly": "Reference label only; forbidden as rule/severity input",
}

CANDIDATE_DESCRIPTIONS = {
    "AUTH_FAILURE": "Action in {Login Failed, Multiple failed logins}, or explicit auth failure phrase in Action/Description/Full_log; not Content",
    "CMD_NMAP": "Command basename equals nmap",
    "CMD_JOHN": "Command basename equals john",
    "CMD_MSFCONSOLE": "Command basename equals msfconsole",
    "CMD_NETCAT": "Command basename in {nc, netcat, socat}; tool presence only, no reverse-shell claim",
    "CMD_CHMOD": "Command basename equals chmod; permissions/arguments require investigation",
    "FILE_CONFIG_CHANGE": "Action in {File modified, File added, File deleted} AND Path matches selected /etc configuration prefixes",
    "FILE_CREDENTIAL_PATH": "Path or Filename ends in passwd/shadow or is under .ssh; visibility only, not proof of theft",
    "FILE_FLAG_PATH": "Path or Filename basename equals flag.txt; exercise-specific, unsuitable as generic attack rule",
    "FILE_ARCHIVE_NAME": "Filename ends in .zip/.rar/.7z/.tar/.gz; contextual observation only",
    "HTTP_TRAVERSAL": "Url after at most two percent-decodes contains ../ or ..\\; payload candidate, not verdict",
    "HTTP_IP_HOST": "Url host parses as a literal IPv4/IPv6; contextual observation only",
}


def explicit_auth_failure(row: dict[str, str]) -> bool:
    if row.get("Action", "").strip().casefold() in {"login failed", "multiple failed logins"}:
        return True
    return any(AUTH_FAILURE_PATTERN.search(row.get(c, "")) for c in ("Action", "Description", "Full_log"))


def candidate_matches(row: dict[str, str]) -> list[str]:
    """Only inspect explicitly named fields; never inspect Anomaly or agent names."""
    matches = []
    if explicit_auth_failure(row):
        matches.append("AUTH_FAILURE")
    command = row.get("Command", "").strip().replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for key, commands in (
        ("CMD_NMAP", {"nmap"}), ("CMD_JOHN", {"john"}),
        ("CMD_MSFCONSOLE", {"msfconsole"}), ("CMD_NETCAT", {"nc", "netcat", "socat"}),
        ("CMD_CHMOD", {"chmod"}),
    ):
        if command in commands:
            matches.append(key)
    path = row.get("Path", "").casefold()
    filename = row.get("Filename", "").casefold()
    if row.get("Action", "") in {"File modified", "File added", "File deleted"} and re.search(
        r"^/etc/(?:apache2/|ssh/|vsftpd\.conf$|passwd$|shadow$|sudoers(?:$|\.d/))", path
    ):
        matches.append("FILE_CONFIG_CHANGE")
    if any(re.search(r"(?:^|/)(?:passwd|shadow)$|(?:^|/)\.ssh(?:/|$)", s) for s in (path, filename)):
        matches.append("FILE_CREDENTIAL_PATH")
    if any(s.rsplit("/", 1)[-1] == "flag.txt" for s in (path, filename)):
        matches.append("FILE_FLAG_PATH")
    if filename.endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
        matches.append("FILE_ARCHIVE_NAME")
    url = row.get("Url", "")
    decoded = unquote(unquote(url))
    if "../" in decoded or "..\\" in decoded:
        matches.append("HTTP_TRAVERSAL")
    try:
        host = urlsplit(url).hostname
        if host:
            ipaddress.ip_address(host)
            matches.append("HTTP_IP_HOST")
    except ValueError:
        pass
    return matches


def source_row_id(digest: str, index: int) -> str:
    return f"{digest}:{index:08d}"


def observed_type(values: Counter[str], column: str) -> str:
    nonempty = [v for v in values if v != ""]
    if not nonempty:
        return "empty"
    if column not in NUMERIC_COLUMNS:
        return "string"
    if all(re.fullmatch(r"[+-]?\d+", v) for v in nonempty):
        return "integer"
    try:
        for v in nonempty:
            float(v)
    except ValueError:
        return "mixed numeric/text"
    return "decimal"


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def survey(input_path: Path, output_dir: Path) -> dict:
    input_path = input_path.resolve()
    output_dir = output_dir.resolve()
    # Do not permit output artifacts to overwrite the source, even with a custom path.
    output_names = {"summary.json", "schema_profile.csv", "login_scan.csv", "login_failure_evidence.json", "candidate_rules.csv", "candidate_examples.json"}
    output_names.update(f"values_{c}.csv" for c in FREQUENCY_COLUMNS)
    if any(output_dir / name == input_path for name in output_names):
        raise ValueError("Output would overwrite input")
    digest = hashlib.sha256(input_path.read_bytes()).hexdigest()
    with input_path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        columns = reader.fieldnames or []
        missing = sorted(set(REQUIRED_COLUMNS) - set(columns))
        if missing or len(columns) != len(set(columns)):
            raise ValueError(f"Missing columns: {missing}; duplicate headers: {len(columns) != len(set(columns))}")
        try:
            rows = list(reader)
        except csv.Error as error:
            raise ValueError(f"Malformed CSV: {error}") from error
    if not rows:
        raise ValueError("Dataset contains no records")
    if any(None in row or any(v is None for v in row.values()) for row in rows):
        raise ValueError("Malformed CSV: record length differs from header")
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = {c: Counter(row[c] for row in rows) for c in columns}
    schema = []
    for c in columns:
        note = SCHEMA_NOTES.get(c, "Additional source column; preserve")
        schema.append({"column": c, "observed_type": observed_type(counts[c], c), "missing_count": counts[c][""], "missing_percent": round(100 * counts[c][""] / len(rows), 6), "unique_nonempty": len(counts[c]) - int("" in counts[c]), "note": note})
    write_csv(output_dir / "schema_profile.csv", list(schema[0]), schema)
    frequency_counts = {c: counts.get(c, Counter({"": len(rows)})) for c in FREQUENCY_COLUMNS}
    for c in FREQUENCY_COLUMNS:
        freq = [{"value": v, "count": n, "percent_all_rows": round(100*n/len(rows), 6), "is_empty": v == ""} for v, n in sorted(frequency_counts[c].items(), key=lambda pair: (-pair[1], pair[0]))]
        write_csv(output_dir / f"values_{c}.csv", list(freq[0]), freq)

    parsed = []
    invalid_timestamp_rows = []
    format_mismatches = []
    scan_records = []
    failures = []
    candidate_counts = Counter()
    examples = {key: [] for key in CANDIDATE_DESCRIPTIONS}
    keyword_counts = Counter()
    services = Counter()
    for index, row in enumerate(rows):
        sid = source_row_id(digest, index)
        evidence = {"source_row_id": sid, "record_index": index, **{c: row.get(c, "") for c in ("id", "Timestamp", "User", "Agent_name", "Activity", "Action", "Command", "Url", "Path", "Filename", "Description", "Full_log", "Content")}}
        try:
            parsed.append(datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S.%f"))
        except ValueError:
            invalid_timestamp_rows.append(sid)
        if not TIMESTAMP_PATTERN.fullmatch(row["Timestamp"]):
            format_mismatches.append(sid)
        matched_columns = []
        tokens = set()
        for c in SCAN_COLUMNS:
            found = sorted({m.group().casefold() for m in LOGIN_PATTERN.finditer(row.get(c, ""))})
            if found:
                matched_columns.append(c)
                keyword_counts[c] += 1
                tokens.update(found)
        if matched_columns:
            scan_records.append({"source_row_id": sid, "id": row["id"], "matched_columns": "|".join(matched_columns), "tokens": "|".join(sorted(tokens)), "explicit_auth_failure": explicit_auth_failure(row)})
        if explicit_auth_failure(row):
            failures.append(evidence)
            service = re.search(r"pam_unix\(([^:()]+):auth\)", row.get("Full_log", ""))
            services[service.group(1) if service else "unparsed"] += 1
        for key in candidate_matches(row):
            candidate_counts[key] += 1
            if len(examples[key]) < 3:
                examples[key].append(evidence)
    write_csv(output_dir / "login_scan.csv", ["source_row_id", "id", "matched_columns", "tokens", "explicit_auth_failure"], scan_records)
    candidates = [{"candidate_id": key, "match_count": candidate_counts[key], "predicate": desc, "status": "supported_signal" if key == "AUTH_FAILURE" and candidate_counts[key] else ("review_candidate" if candidate_counts[key] else "disabled_no_match")} for key, desc in CANDIDATE_DESCRIPTIONS.items()]
    write_csv(output_dir / "candidate_rules.csv", list(candidates[0]), candidates)
    users_missing = sum(not row["User"].strip() for row in rows)
    summary = {
        "source": str(input_path), "sha256": digest, "bytes": input_path.stat().st_size,
        "python_version": platform.python_version(), "dependencies": "Python standard library only",
        "record_count": len(rows), "column_count": len(columns), "schema": schema,
        "id_missing": counts["id"][""], "duplicate_id_rows_beyond_first": len(rows)-len(counts["id"]),
        "duplicate_full_rows_beyond_first": len(rows)-len({tuple(row[c] for c in columns) for row in rows}),
        "timestamp": {"expected_format": "%Y-%m-%d %H:%M:%S.%f (exactly 3 fraction digits)", "timezone": "not encoded; no timezone assumption", "invalid_count": len(invalid_timestamp_rows), "invalid_source_row_ids": invalid_timestamp_rows, "format_mismatch_count": len(format_mismatches), "min": min(parsed).isoformat() if parsed else None, "max": max(parsed).isoformat() if parsed else None, "ascending": all(a <= b for a,b in zip(parsed, parsed[1:])), "descending": all(a >= b for a,b in zip(parsed, parsed[1:]))},
        "frequencies": {c: dict(frequency_counts[c].most_common(10)) for c in FREQUENCY_COLUMNS},
        "absent_frequency_columns": [c for c in FREQUENCY_COLUMNS if c not in columns],
        "unique_nonempty": {c: len(counts[c])-int("" in counts[c]) for c in columns},
        "login_scan": {"pattern": LOGIN_PATTERN.pattern, "explicit_pattern": AUTH_FAILURE_PATTERN.pattern, "keyword_rows": len(scan_records), "rows_by_column": dict(keyword_counts), "explicit_failure_rows": len(failures), "failure_action_counts": dict(Counter(r["Action"] for r in failures)), "failure_services": dict(services), "failure_missing_users": sum(not r["User"].strip() for r in failures), "failure_rule_decision": "enable explicit authentication-failure candidate" if failures else "disable: no explicit signal"},
        "candidate_rules": candidates, "missing_user_rows": users_missing,
        "quality": {"negative_size_before": sum(float(row["Size_before"]) < 0 for row in rows if row.get("Size_before")), "command_rows_missing_command": sum(row["Activity"] == "command" and not row.get("Command") for row in rows), "srcip_present": "Srcip" in columns},
        "missing_definition": "Empty CSV field only; NA/null-like strings and whitespace are preserved, not silently converted",
        "row_id_format": "sha256_of_original_file:zero_based_record_index_padded_to_8_digits",
    }
    for name, value in (("summary.json", summary), ("login_failure_evidence.json", failures), ("candidate_examples.json", examples)):
        (output_dir / name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    if hashlib.sha256(input_path.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Input changed during survey; outputs must be regenerated")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/schema_profiling"))
    args = parser.parse_args()
    summary = survey(args.input, args.output)
    print(json.dumps({"output": str(args.output), "records": summary["record_count"], "columns": summary["column_count"], "sha256": summary["sha256"], "login_scan": summary["login_scan"], "candidates": summary["candidate_rules"]}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
