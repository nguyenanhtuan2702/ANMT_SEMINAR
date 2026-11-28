"""Task 9 adversarial inputs, correlation boundaries and reproducibility."""
from io import BytesIO
from pathlib import Path

import pandas as pd
import pytest

from dashboard.service import run_upload_pipeline
from detection.correlation import correlate, get_timeline
from detection.pipeline import run_detection_pipeline
from preprocessing.log_loader import LogLoadError
from test_pipeline import csv_bytes


def payload_with(**columns):
    frame = pd.read_csv(BytesIO(csv_bytes()), keep_default_na=False, dtype="string")
    frame["Decoder_name"] = "auditd"
    for name, values in columns.items():
        frame[name] = values
    return frame.to_csv(index=False).encode("utf-8")


@pytest.mark.parametrize("payload", [b"", b"\xef\xbb\xbf", b" \r\n\t", csv_bytes(count=0)],
                         ids=["empty", "BOM-only", "whitespace-only", "header-only"])
def test_empty_uploads_fail_with_explicit_report(payload):
    with pytest.raises(LogLoadError) as failure:
        run_upload_pipeline(BytesIO(payload))
    assert failure.value.report["status"] == "error"
    assert failure.value.report["rows_loaded"] == 0


@pytest.mark.parametrize("column", ["id", "Timestamp", "Activity", "Action", "User", "Agent_name"])
def test_missing_required_column_names_the_column(column):
    source = pd.read_csv(BytesIO(csv_bytes()), keep_default_na=False)
    with pytest.raises(LogLoadError, match=column) as failure:
        run_upload_pipeline(BytesIO(source.drop(columns=column).to_csv(index=False).encode()))
    assert column in failure.value.report["missing_columns"]


@pytest.mark.parametrize("timestamp", ["not-a-date", "2025-02-30 12:00:00.000", "2025-03-06T12:00:00Z"],
                         ids=["invalid-format", "impossible-date", "unexpected-timezone"])
def test_invalid_timestamp_rows_are_flagged_and_retained(timestamp):
    result = run_upload_pipeline(BytesIO(payload_with(Timestamp=timestamp)))
    logs = result["detected_logs"]
    assert len(logs) == 4 and logs.invalid_timestamp.all()
    assert logs.timestamp_error.notna().all()
    assert logs.Timestamp.isna().all()
    assert logs.group_id.isna().all() and logs.severity.isna().all()
    assert logs.alert_count.eq(0).all() and result["alerts"] == []
    assert result["report"]["rules"]["rows_invalid_time"] == 4


@pytest.mark.parametrize("column", ["User", "Command", "Path", "Url", "Decoder_name", "Full_log", "Description", "Content"])
def test_all_empty_optional_column_is_handled_without_losing_rows(column):
    result = run_upload_pipeline(BytesIO(payload_with(**{column: ""})))
    logs = result["detected_logs"]
    assert len(logs) == 4 and result["status"] == "success"
    if column == "User":
        assert logs.User.isna().all() and logs.group_id.isna().all()
        assert len(result["alerts"]) == 4
    elif column == "Command":
        assert result["alerts"] == [] and logs.severity.isna().all()
    else:
        assert len(result["alerts"]) == 4
    if column in {"Full_log", "Description", "Content"}:
        assert logs[column].eq("").all()


@pytest.mark.parametrize("column", ["Timestamp", "Agent_name", "Activity", "Action", "id"])
def test_all_empty_required_column_is_rejected_instead_of_silently_dropped(column):
    with pytest.raises(LogLoadError, match=column):
        run_upload_pipeline(BytesIO(payload_with(**{column: ""})))


def test_one_row_user_and_timeline_have_valid_counts_and_evidence():
    result = run_upload_pipeline(BytesIO(csv_bytes(count=1)))
    logs = result["detected_logs"]
    assert len(logs) == len(result["alerts"]) == len(result["groups"]) == 1
    group = result["groups"].iloc[0]
    assert group.event_count == group.alert_count == 1
    normalized = logs.drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    timeline = get_timeline(normalized, group.group_id, result["alerts"])
    assert timeline.source_row_id.tolist() == logs.source_row_id.tolist()
    assert timeline.has_alert.tolist() == [True]
    assert timeline.Full_log.iloc[0] == ' Raw "quoted",\r\n '


def test_unsorted_duplicate_timestamp_rows_are_causal_and_order_independent():
    result = run_upload_pipeline(BytesIO(payload_with(Timestamp="2025-03-06 12:00:00.123")))
    normalized = result["detected_logs"].drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    shuffled = normalized.iloc[[3, 1, 0, 2]].copy()
    shuffled.index = [10, 10, 1, 0]
    rerun = run_detection_pipeline(shuffled)
    assert rerun["alerts"] == result["alerts"]
    pd.testing.assert_frame_equal(rerun["groups"], result["groups"], check_exact=True)
    assert rerun["groups"].source_row_ids.iloc[0] == normalized.source_row_id.tolist()
    assert result["detected_logs"].severity.tolist() == ["MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_same_upload_twice_reproduces_all_semantic_outputs():
    raw = payload_with(User=["alice", "bob", "alice", "alice"])
    first, second = run_upload_pipeline(BytesIO(raw)), run_upload_pipeline(BytesIO(raw))
    assert first["atomic_alerts"] == second["atomic_alerts"]
    assert first["alerts"] == second["alerts"]
    for key in ["groups", "alert_table", "detected_logs"]:
        pd.testing.assert_frame_equal(first[key], second[key], check_exact=True)
    # Elapsed times are measurements, not deterministic detection content.
    for key in ["atomic_alert_count", "alerted_event_count", "group_count", "events_without_group"]:
        assert first["report"][key] == second["report"][key]


@pytest.mark.parametrize("storage", ["python", "pyarrow"])
def test_nullable_string_backends_preserve_activity_rule_and_source_lists(storage):
    result = run_upload_pipeline(BytesIO(csv_bytes(count=3)))
    normalized = result["detected_logs"].drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    for column in ["source_row_id", "User", "Agent_name", "Activity"]:
        normalized[column] = normalized[column].astype(pd.StringDtype(storage=storage))
    groups = correlate(normalized, result["atomic_alerts"])
    assert groups.activities.iloc[0] == ["command"]
    assert groups.rule_ids.iloc[0] == ["CMD_NMAP"]
    assert groups.source_row_ids.iloc[0] == normalized.source_row_id.tolist()
    assert groups.alert_count.iloc[0] == 3


def test_future_user_does_not_renumber_existing_singleton_group():
    first = run_upload_pipeline(BytesIO(csv_bytes(count=1)))["detected_logs"]
    first = first.drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    later = first.copy(deep=True)
    later["User"] = "another-user"
    later["Timestamp"] += pd.Timedelta(seconds=1)
    later["record_index"] = 999
    later["source_row_id"] = later.source_row_id.str.rsplit(":", n=1).str[0] + ":00000999"
    before = correlate(first, [])
    after = correlate(pd.concat([later, first], ignore_index=True), [])
    assert before.group_id.iloc[0] in after.group_id.tolist()
    assert after.loc[after.group_id.eq(before.group_id.iloc[0]), "source_row_ids"].iloc[0] == first.source_row_id.tolist()


def test_model_load_cache_reuses_artifact_and_invalidates_replaced_file(tmp_path, monkeypatch):
    from detection import ml_engine
    path = tmp_path/"model.joblib"
    path.write_bytes(b"first")
    calls = []

    def fake_load(filename):
        calls.append(filename)
        return Path(filename).read_bytes()

    monkeypatch.setattr(ml_engine.joblib, "load", fake_load)
    ml_engine._load_pipeline.cache_clear()
    try:
        version = path.stat()
        assert ml_engine._load_pipeline(str(path), version.st_mtime_ns, version.st_size) == b"first"
        assert ml_engine._load_pipeline(str(path), version.st_mtime_ns, version.st_size) == b"first"
        assert len(calls) == 1
        path.write_bytes(b"replacement")
        version = path.stat()
        assert ml_engine._load_pipeline(str(path), version.st_mtime_ns, version.st_size) == b"replacement"
        assert len(calls) == 2
    finally:
        ml_engine._load_pipeline.cache_clear()


@pytest.fixture(scope="module")
def full_dataset_runs():
    source = Path("data/raw/logs_SPEDIA_annotated_en.csv")
    if not source.is_file():
        pytest.skip("The local full SPEDIA CSV is required for the full_dataset test.")
    raw = source.read_bytes()
    return raw, run_upload_pipeline(BytesIO(raw)), run_upload_pipeline(BytesIO(raw))


@pytest.mark.full_dataset
def test_full_72250_row_file_has_no_silent_loss_and_matches_frozen_features(full_dataset_runs):
    from preprocessing.data_bundle import load_table
    raw, first, _ = full_dataset_runs
    logs = first["detected_logs"]
    assert len(raw) == 45703322 and len(logs) == 72250
    assert len(first["alerts"]) == 1301 and len(first["groups"]) == 7501
    assert first["report"]["load"]["rows_skipped"] == 0
    frozen = load_table("detected_logs.csv")
    for column in ["source_row_id", "record_index", "rule_ids", "alert_count", "group_id", "severity", "Full_log", "Description", "Content"]:
        pd.testing.assert_series_equal(logs[column], frozen[column], check_exact=True)
    pd.testing.assert_frame_equal(first["groups"], load_table("event_groups.csv"), check_exact=True)


@pytest.mark.full_dataset
def test_full_dataset_two_runs_reproduce_alerts_groups_and_detected_rows(full_dataset_runs):
    _, first, second = full_dataset_runs
    assert first["alerts"] == second["alerts"]
    assert first["atomic_alerts"] == second["atomic_alerts"]
    for key in ["groups", "alert_table", "detected_logs"]:
        pd.testing.assert_frame_equal(first[key], second[key], check_exact=True)
