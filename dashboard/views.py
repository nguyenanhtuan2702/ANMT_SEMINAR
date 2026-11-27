"""Streamlit rule-based dashboard using the tested upload pipeline."""
import hashlib
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.service import run_upload_pipeline
from detection.correlation import get_timeline

ROOT = Path(__file__).resolve().parents[1]


@st.cache_data(show_spinner=False, max_entries=2)
def process_upload_bytes(raw: bytes, rules_hash: str, policy_hash: str):
    # Hash arguments invalidate cached results when detection policy changes.
    return run_upload_pipeline(BytesIO(raw))


@st.cache_data(show_spinner=False, max_entries=8)
def timeline_for_upload(raw: bytes, group_id: str, rules_hash: str, policy_hash: str):
    result = process_upload_bytes(raw, rules_hash, policy_hash)
    original = result["detected_logs"].drop(columns=["rule_ids", "alert_count", "group_id", "severity"])
    return get_timeline(original, group_id, result["alerts"], config=result["report"]["severity_policy"]["correlation"])


def render_dashboard():
    st.set_page_config(page_title="AI Security Log Analyzer", layout="wide")
    st.title("AI Security Log Analyzer")
    st.caption("Rule-based SPEDIA • Severity is prototype processing priority, not verified impact")
    file = st.sidebar.file_uploader("Upload original CSV logs", type=["csv"])
    if file is None:
        st.info("Select logs_SPEDIA_annotated_en.csv to normalize logs and run detection.")
        return
    try:
        raw = file.getvalue()
        rules_hash = hashlib.sha256((ROOT/"detection/rules.json").read_bytes()).hexdigest()
        policy_hash = hashlib.sha256((ROOT/"detection/severity_policy.json").read_bytes()).hexdigest()
        with st.spinner("Normalizing and analyzing logs…"):
            result = process_upload_bytes(raw, rules_hash, policy_hash)
    except (ValueError, TypeError, UnicodeError, OSError) as error:
        st.error(str(error))
        return
    df, groups = result["detected_logs"], result["groups"]
    overview, events, alerts, timeline_tab, evaluation = st.tabs(
        ["Overview", "Events", "Alerts", "Timeline", "ML evaluation"])
    with overview:
        st.success("Rule-based analysis completed.")
        a, b, c = st.columns(3)
        a.metric("Events", f"{len(df):,}")
        b.metric("Alerted events", f"{len(result['alerts']):,}")
        c.metric("Event groups", f"{len(groups):,}")
        st.bar_chart(df.Activity.fillna("No information").value_counts())
        st.dataframe(pd.DataFrame(list(result["report"]["timings_seconds"].items()), columns=["Step", "Seconds"]), hide_index=True)
        st.caption(f"{result['report']['events_without_group']:,} events lack sufficient grouping data; they remain in the event list.")
    with events:
        c1, c2, c3 = st.columns(3)
        activities = c1.multiselect("Activity", sorted(df.Activity.dropna().unique()))
        users = c2.multiselect("User", sorted(df.User.dropna().unique()))
        agents = c3.multiselect("Host / Agent", sorted(df.Agent_name.dropna().unique()))
        include_missing = st.checkbox("Include events with missing usernames when filtering by User", value=False)
        mask = pd.Series(True, index=df.index)
        if activities: mask &= df.Activity.isin(activities)
        if users: mask &= df.User.isin(users) | (df.User.isna() if include_missing else False)
        if agents: mask &= df.Agent_name.isin(agents)
        view = df.loc[mask].drop(columns="Anomaly", errors="ignore")
        st.write(f"{len(view):,} / {len(df):,} events match the filters.")
        st.caption("Showing up to 1,000 rows; filters apply only to the Events tab.")
        st.dataframe(view.head(1000), hide_index=True)
    with alerts:
        if not result["alerts"]:
            st.info("Detection completed successfully with no matching alerts.")
        else:
            table = result["alert_table"].drop(columns="rule_matches")
            st.dataframe(table, hide_index=True)
            selected = st.selectbox("View alert evidence", [a["source_row_id"] for a in result["alerts"]])
            alert = next(a for a in result["alerts"] if a["source_row_id"] == selected)
            for match in alert["rule_matches"]:
                st.write(match["rule_id"], match["reason"])
                st.write(match["severity_reason"])
                st.json(match["evidence"])
            st.dataframe(df.loc[df.source_row_id.eq(selected)].drop(columns="Anomaly", errors="ignore"), hide_index=True)
    with timeline_tab:
        st.caption("The timeline is a snapshot of the uploaded file. Final group statistics are not features for past events.")
        if groups.empty:
            st.info("No groups have sufficient data.")
        else:
            selected_group = st.selectbox("Event groups", groups.group_id.tolist())
            timeline = timeline_for_upload(raw, selected_group, rules_hash, policy_hash)
            st.dataframe(timeline, hide_index=True)
    with evaluation:
        st.info("ML has not run. Anomaly is a reference label for evaluation, not an application prediction.")
