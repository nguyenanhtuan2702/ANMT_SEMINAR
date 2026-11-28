"""Streamlit dashboard for independent Rule and ML results."""
import hashlib
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.service import (
    DEFAULT_MODEL,
    EVENT_FILTERS,
    MODEL_LABELS,
    MODEL_NAMES,
    filter_dashboard_events,
    join_rule_ml_results,
    model_artifact_version,
    resolve_model_threshold,
    run_ml_inference,
    run_upload_pipeline,
)
from detection.correlation import get_timeline

ROOT = Path(__file__).resolve().parents[1]
COMPARISON_FILTER_LABELS = {
    "All Events": "All Events",
    "ML Anomaly Only": "ML Anomaly Only",
    "Rule Alerts Only": "Rule Alerts Only",
    "Both Rule and ML": "Both Rule and ML",
    "ML Only": "ML Only",
    "Rule Only": "Rule Only",
    "Neither": "Neither",
    "Not Evaluated": "Not Evaluated",
}


@st.cache_data(show_spinner=False, max_entries=2)
def process_upload_bytes(raw: bytes, rules_hash: str, policy_hash: str):
    # Model controls do not participate in this cache key, so changing ML
    # settings leaves the Rule pipeline result reusable.
    return run_upload_pipeline(BytesIO(raw))


@st.cache_data(show_spinner=False, max_entries=8)
def ml_for_upload(
    source_file_hash: str,
    normalized_events: pd.DataFrame,
    model_name: str,
    threshold: float,
    artifact_version: str,
):
    # This cache is independent of process_upload_bytes and includes every
    # inference input, including model artifact version.
    return run_ml_inference(normalized_events, model_name, threshold)


@st.cache_data(show_spinner=False, max_entries=8)
def timeline_for_upload(raw: bytes, group_id: str, rules_hash: str, policy_hash: str):
    result = process_upload_bytes(raw, rules_hash, policy_hash)
    original = result["detected_logs"].drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    return get_timeline(original, group_id, result["alerts"], config=result["report"]["severity_policy"]["correlation"])


def _ml_controls():
    selected_model = st.sidebar.selectbox(
        "ML model",
        MODEL_NAMES,
        index=MODEL_NAMES.index(DEFAULT_MODEL),
        format_func=lambda name: MODEL_LABELS[name],
        key="ml_model_selector",
    )
    configured_threshold, threshold_notice = resolve_model_threshold(selected_model)
    remembered_model = st.session_state.get("_threshold_model")
    if remembered_model != selected_model:
        st.session_state["ml_threshold"] = configured_threshold
        st.session_state["_threshold_model"] = selected_model
    threshold = st.sidebar.slider(
        "Anomaly threshold",
        min_value=0.0,
        max_value=1.0,
        step=0.01,
        key="ml_threshold",
        format="%.4f",
    )
    if threshold_notice:
        st.sidebar.warning(threshold_notice)
    else:
        st.sidebar.caption(f"Default from reports/ml/model_thresholds.json: {configured_threshold:.4f}")
    return selected_model, float(threshold), threshold_notice


def render_dashboard():
    st.set_page_config(page_title="AI Security Log Analyzer", layout="wide")
    st.title("AI Security Log Analyzer")
    st.caption("Rules and ML analyze the same normalized events. Severity remains a Rule policy priority.")
    file = st.sidebar.file_uploader("Upload original CSV logs", type=["csv"])
    if file is None:
        st.info("Select a CSV to normalize logs and run Rule and ML analysis.")
        return

    selected_model, threshold, _ = _ml_controls()
    try:
        raw = file.getvalue()
        source_file_hash = hashlib.sha256(raw).hexdigest()
        rules_hash = hashlib.sha256((ROOT / "detection/rules.json").read_bytes()).hexdigest()
        policy_hash = hashlib.sha256((ROOT / "detection/severity_policy.json").read_bytes()).hexdigest()
        with st.spinner("Normalizing and analyzing logs with Rules…"):
            result = process_upload_bytes(raw, rules_hash, policy_hash)
    except (ValueError, TypeError, UnicodeError, OSError) as error:
        st.error(str(error))
        return

    detected, groups = result["detected_logs"], result["groups"]
    ml_results = None
    ml_error = None
    try:
        artifact_version = model_artifact_version(selected_model)
        with st.spinner("Running ML inference on the full event set…"):
            ml_results = ml_for_upload(
                source_file_hash,
                result["normalized_logs"],
                selected_model,
                threshold,
                artifact_version,
            )
    except Exception as error:
        # Inference is optional to the Rule workflow: report its error and keep
        # every Rule-based view available.
        ml_error = str(error)

    combined = join_rule_ml_results(result["normalized_logs"], detected, ml_results)
    if ml_error:
        st.warning(f"ML inference failed. Rule results are still available. Details: {ml_error}")

    overview, events, alerts, timeline_tab, evaluation = st.tabs(
        ["Overview", "Events", "Alerts", "Timeline", "ML evaluation"]
    )
    with overview:
        st.success("Rule-based analysis completed.")
        if ml_error:
            st.info("ML evaluation is unavailable for this upload; missing predictions are marked Not Evaluated.")
        a, b, c = st.columns(3)
        a.metric("Events", f"{len(detected):,}")
        b.metric("Rule alerts", f"{int(combined['Rule Alert'].sum()):,}")
        c.metric("Event groups", f"{len(groups):,}")
        st.bar_chart(detected.Activity.fillna("No information").value_counts())
        st.dataframe(
            pd.DataFrame(list(result["report"]["timings_seconds"].items()), columns=["Step", "Seconds"]),
            hide_index=True,
        )
        st.caption(f"{result['report']['events_without_group']:,} events lack sufficient grouping data; they remain in the event list.")
    with events:
        group_filter = st.selectbox("Comparison filter", EVENT_FILTERS, key="events_comparison_filter")
        c1, c2, c3 = st.columns(3)
        activities = c1.multiselect("Activity", sorted(detected.Activity.dropna().unique()))
        users = c2.multiselect("User", sorted(detected.User.dropna().unique()))
        agents = c3.multiselect("Host / Agent", sorted(detected.Agent_name.dropna().unique()))
        include_missing = st.checkbox("Include events with missing usernames when filtering by User", value=False)
        view = filter_dashboard_events(
            combined,
            comparison_filter=group_filter,
            activities=activities,
            users=users,
            agents=agents,
            include_missing_user=include_missing,
        )
        count_a, count_b, count_c = st.columns(3)
        count_a.metric("Matching events", f"{len(view):,}")
        count_b.metric("Rule alerts in view", f"{int(view['Rule Alert'].sum()):,}")
        count_c.metric("ML anomalies in view", f"{int(view['ML Prediction'].eq('Anomaly').sum()):,}")
        st.caption("Filters affect display only. Rules and ML were run on the complete uploaded event set.")
        display = view.drop(columns=["Anomaly", "Level"], errors="ignore").rename(
            columns={"source_row_id": "Source Row ID", "severity": "Severity", "anomaly_score": "Anomaly Score"}
        )
        st.dataframe(display.head(1000), hide_index=True)
    with alerts:
        if not result["alerts"]:
            st.info("Detection completed successfully with no matching alerts.")
        else:
            table = result["alert_table"].drop(columns="rule_matches")
            st.dataframe(table, hide_index=True)
            selected = st.selectbox("View alert evidence", [alert["source_row_id"] for alert in result["alerts"]])
            alert = next(item for item in result["alerts"] if item["source_row_id"] == selected)
            for match in alert["rule_matches"]:
                st.write(match["rule_id"], match["reason"])
                st.write(match["severity_reason"])
                st.json(match["evidence"])
            st.dataframe(detected.loc[detected.source_row_id.eq(selected)].drop(columns=["Anomaly", "Level"], errors="ignore"), hide_index=True)
    with timeline_tab:
        st.caption("The timeline is a snapshot of the uploaded file. Final group statistics are not features for past events.")
        if groups.empty:
            st.info("No groups have sufficient data.")
        else:
            selected_group = st.selectbox("Event groups", groups.group_id.tolist())
            timeline = timeline_for_upload(raw, selected_group, rules_hash, policy_hash)
            st.dataframe(timeline, hide_index=True)
    with evaluation:
        st.write(f"Model: **{MODEL_LABELS[selected_model]}** (`{selected_model}`) · threshold: **{threshold:.4f}**")
        if ml_error:
            st.error(f"No ML results for this run. {ml_error}")
        else:
            st.success(f"ML completed for {int(combined['ML Prediction'].ne('Not Evaluated').sum()):,} events.")
        evaluated = combined.loc[combined["Comparison Group"].ne("Not Evaluated")]
        groups_count = evaluated["Comparison Group"].value_counts()
        metric_columns = st.columns(8)
        metrics = [
            ("Evaluated", len(evaluated)),
            ("Rule alerts", int(combined["Rule Alert"].sum())),
            ("ML anomalies", int(evaluated["ML Prediction"].eq("Anomaly").sum())),
            ("Both", int(groups_count.get("Both", 0))),
            ("Rule Only", int(groups_count.get("Rule Only", 0))),
            ("ML Only", int(groups_count.get("ML Only", 0))),
            ("Neither", int(groups_count.get("Neither", 0))),
            ("Not Evaluated", int(combined["Comparison Group"].eq("Not Evaluated").sum())),
        ]
        for column, (label, value) in zip(metric_columns, metrics):
            column.metric(label, f"{value:,}")
        st.caption("Both, Rule Only, ML Only and Neither partition evaluated events. Not Evaluated rows are excluded from these counts.")

        comparison_options = ["All Events", "Both", "Rule Only", "ML Only", "Neither", "Not Evaluated"]
        comparison_filter = st.selectbox("Comparison group", comparison_options, key="evaluation_group_filter")
        comparison_view = combined if comparison_filter == "All Events" else combined.loc[combined["Comparison Group"].eq(comparison_filter)]
        comparison_columns = [
            "source_row_id", "Rule Alert", "severity", "ML Prediction", "anomaly_score", "Comparison Group"
        ]
        table = comparison_view[comparison_columns].rename(
            columns={"source_row_id": "Source Row ID", "severity": "Severity", "anomaly_score": "Anomaly Score"}
        )
        st.dataframe(table.head(1000), hide_index=True)

        query = st.text_input("Find event by source_row_id", key="comparison_source_id_search").strip()
        inspect_rows = comparison_view
        if query:
            inspect_rows = inspect_rows.loc[inspect_rows["source_row_id"].astype("string").str.contains(query, regex=False, na=False)]
        inspect_ids = inspect_rows["source_row_id"].head(1000).tolist()
        if inspect_ids:
            selected_id = st.selectbox("Inspect event", inspect_ids, key="comparison_event_details")
            event = combined.loc[combined["source_row_id"].eq(selected_id)].drop(
                columns=["Anomaly", "Level"], errors="ignore"
            )
            st.dataframe(event, hide_index=True)
        elif query:
            st.info("No event matches that source_row_id search.")
