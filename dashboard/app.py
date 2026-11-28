"""Streamlit dashboard for integrated SPEDIA log analysis."""
from pathlib import Path
import hashlib
import json

import pandas as pd
import streamlit as st

from detection.pipeline import analyze_events
from preprocessing.log_loader import load_log_csv


st.set_page_config(page_title="AI Security Log Analyzer", layout="wide")
st.title("AI Security Log Analyzer")
st.caption(
    "Phân tích nhật ký bằng Machine Learning và Rule Engine, "
    "liên kết sự kiện và ưu tiên cảnh báo."
)

uploaded_file = st.sidebar.file_uploader("Tải nhật ký CSV", type=["csv"])
model_name = st.sidebar.selectbox(
    "Mô hình ML",
    options=[
        "random_forest_behavioral.joblib",
        "random_forest.joblib",
        "logistic_regression.joblib",
    ],
)
threshold_path = (
    Path(__file__).resolve().parents[1]
    / "reports"
    / "ml"
    / "model_thresholds.json"
)
model_thresholds = (
    json.loads(threshold_path.read_text(encoding="utf-8"))
    if threshold_path.exists()
    else {}
)
recommended_threshold = round(float(model_thresholds.get(model_name, 0.52)), 2)
recommended_threshold = min(max(recommended_threshold, 0.05), 0.95)
threshold = st.sidebar.slider(
    "Ngưỡng anomaly",
    min_value=0.05,
    max_value=0.95,
    value=recommended_threshold,
    step=0.01,
    key=f"anomaly_threshold_{model_name}",
)
st.sidebar.caption("Mặc định theo validation; có thể điều chỉnh.")

if uploaded_file is None:
    st.info("Tải file CSV có schema log SPEDIA để bắt đầu phân tích.")
    st.stop()

try:
    file_bytes = uploaded_file.getvalue()
    analysis_key = (
        hashlib.sha256(file_bytes).hexdigest(),
        model_name,
        threshold,
    )
    if st.session_state.get("analysis_key") == analysis_key:
        analysis = st.session_state["analysis"]
    else:
        raw_events = load_log_csv(file_bytes)
        with st.spinner("Đang chuẩn hóa log, chạy ML/Rules và liên kết sự kiện..."):
            analysis = analyze_events(
                raw_events,
                model_name=model_name,
                threshold=threshold,
            )
        st.session_state["analysis_key"] = analysis_key
        st.session_state["analysis"] = analysis
except (ValueError, FileNotFoundError) as error:
    st.error(f"Không thể phân tích file: {error}")
    st.stop()

events = analysis["events"]
alerts = analysis["alerts"]
groups = analysis["event_groups"]
diagnostics = analysis["diagnostics"]
st.sidebar.success(f"Đã nạp {uploaded_file.name} • {len(events):,} sự kiện")
if diagnostics["invalid_timestamp_rows"]:
    st.warning(
        f"Bỏ qua {diagnostics['invalid_timestamp_rows']:,} sự kiện có Timestamp "
        "không hợp lệ khi chạy detector/correlation; các dòng vẫn được giữ trong bảng sự kiện."
    )

overview, event_tab, alert_tab, investigation, evaluation = st.tabs(
    ["Tổng quan", "Sự kiện", "Cảnh báo", "Điều tra", "Đánh giá ML"]
)

with overview:
    st.subheader("Tình trạng phân tích")
    metric_columns = st.columns(4)
    metric_columns[0].metric("Số sự kiện", f"{diagnostics['input_rows']:,}")
    metric_columns[1].metric("Cảnh báo ML", f"{diagnostics['ml_alerts']:,}")
    metric_columns[2].metric("Cảnh báo rules", f"{diagnostics['rule_alerts']:,}")
    metric_columns[3].metric("Nhóm tương quan", f"{diagnostics['correlated_groups']:,}")

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.subheader("Sự kiện theo hoạt động")
        st.bar_chart(
            events["Activity"].fillna("Không có thông tin").value_counts(),
            y_label="Số sự kiện",
        )
    with chart_right:
        st.subheader("Cảnh báo theo ngày")
        if alerts.empty:
            st.info("Chưa có cảnh báo.")
        else:
            daily_alerts = (
                alerts.assign(date=pd.to_datetime(alerts["timestamp"]).dt.floor("D"))
                .groupby("date")
                .size()
                .rename("Số cảnh báo")
            )
            st.line_chart(daily_alerts, y_label="Số cảnh báo")

    st.subheader("Cảnh báo theo detector")
    if alerts.empty:
        st.info("Không có cảnh báo từ các detector đã chạy.")
    else:
        st.bar_chart(
            alerts["source"].value_counts().rename("Số cảnh báo"),
            y_label="Số cảnh báo",
        )
    st.caption(
        f"ML đã chấm điểm {diagnostics['ml_scored_rows']:,} sự kiện có Timestamp hợp lệ; "
        f"{diagnostics['events_without_correlation_group']:,} sự kiện không đủ điều kiện "
        "correlation (ví dụ thiếu User hoặc Agent)."
    )

with event_tab:
    st.subheader("Danh sách sự kiện đã chuẩn hóa")
    activity_options = sorted(events["Activity"].dropna().astype(str).unique())
    user_options = sorted(events["User"].dropna().astype(str).unique())
    agent_options = sorted(events["Agent_name"].dropna().astype(str).unique())
    first, second, third = st.columns(3)
    selected_activities = first.multiselect("Activity", activity_options)
    selected_users = second.multiselect("User", user_options)
    selected_agents = third.multiselect("Agent", agent_options)
    filtered_events = events.copy()
    valid_timestamps = events["Timestamp"].dropna()
    if not valid_timestamps.empty:
        min_date = valid_timestamps.min().date()
        max_date = valid_timestamps.max().date()
        date_left, date_right = st.columns(2)
        start_date = date_left.date_input(
            "Từ ngày",
            value=min_date,
            min_value=min_date,
            max_value=max_date,
        )
        end_date = date_right.date_input(
            "Đến ngày",
            value=max_date,
            min_value=min_date,
            max_value=max_date,
        )
        if start_date <= end_date:
            dates = events["Timestamp"].dt.date
            filtered_events = filtered_events[
                dates.between(start_date, end_date) | dates.isna()
            ]
        else:
            st.warning("Ngày bắt đầu phải trước hoặc bằng ngày kết thúc.")
    if selected_activities:
        filtered_events = filtered_events[
            filtered_events["Activity"].astype("string").isin(selected_activities)
        ]
    if selected_users:
        filtered_events = filtered_events[
            filtered_events["User"].astype("string").isin(selected_users)
        ]
    if selected_agents:
        filtered_events = filtered_events[
            filtered_events["Agent_name"].astype("string").isin(selected_agents)
        ]
    st.write(f"Có {len(filtered_events):,} / {len(events):,} sự kiện phù hợp.")
    st.caption("Hiển thị tối đa 1.000 dòng; raw log được giữ để analyst đối chiếu.")
    st.dataframe(filtered_events.head(1000), use_container_width=True)
    if "Anomaly" in events.columns:
        st.caption("Anomaly là nhãn tham chiếu trong file, không phải dự đoán của app.")

with alert_tab:
    st.subheader("Cảnh báo ML và Rule Engine")
    if alerts.empty:
        st.success("Các detector đã chạy nhưng không sinh cảnh báo.")
    else:
        left, right = st.columns(2)
        sources = left.multiselect(
            "Nguồn cảnh báo",
            sorted(alerts["source"].dropna().astype(str).unique()),
        )
        severities = right.multiselect(
            "Mức ưu tiên",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        )
        visible_alerts = alerts.copy()
        if sources:
            visible_alerts = visible_alerts[visible_alerts["source"].isin(sources)]
        if severities:
            visible_alerts = visible_alerts[visible_alerts["severity"].isin(severities)]
        st.write(f"Hiển thị {len(visible_alerts):,} cảnh báo.")
        columns = [
            column
            for column in [
                "timestamp",
                "source",
                "severity",
                "rule_id",
                "user",
                "agent",
                "activity",
                "action",
                "anomaly_score",
                "reason",
                "severity_reason",
                "group_id",
                "source_row_id",
            ]
            if column in visible_alerts.columns
        ]
        st.dataframe(visible_alerts[columns], use_container_width=True)

with investigation:
    st.subheader("Correlation và timeline")
    if groups.empty:
        st.info("Không có sự kiện đủ thông tin để tạo nhóm tương quan.")
    else:
        st.caption(
            "Nhóm theo User + Agent trong fixed window 15 phút; tách nhóm khi "
            "khoảng cách giữa hai sự kiện lớn hơn 5 phút. Nhóm là ngữ cảnh điều tra, "
            "không tự xác nhận một chuỗi tấn công."
        )
        st.dataframe(
            groups[
                [
                    "group_id",
                    "user",
                    "agent",
                    "start_time",
                    "end_time",
                    "event_count",
                    "alert_count",
                    "rule_ids",
                    "activities",
                ]
            ].head(1000),
            use_container_width=True,
        )
        selected_group = st.selectbox("Chọn group_id để xem timeline", groups["group_id"])
        group = groups.loc[groups["group_id"] == selected_group].iloc[0]
        member_ids = set(group["source_row_ids"])
        st.write(
            f"{group['event_count']} sự kiện • User {group['user']} • "
            f"Agent {group['agent']} • {group['start_time']} → {group['end_time']}"
        )
        st.dataframe(
            events[events["source_row_id"].isin(member_ids)].sort_values(
                ["Timestamp", "record_index"], kind="stable"
            ),
            use_container_width=True,
        )
        related_alerts = alerts[alerts["group_id"] == selected_group]
        st.subheader("Cảnh báo trong nhóm")
        if related_alerts.empty:
            st.info("Nhóm này không có alert.")
        else:
            st.dataframe(related_alerts, use_container_width=True)

with evaluation:
    st.subheader("Kết quả thực nghiệm đã lưu")
    report_dir = Path(__file__).resolve().parents[1] / "reports" / "ml"
    metric_path = report_dir / "model_metrics.csv"
    if metric_path.exists():
        metrics = pd.read_csv(metric_path)
        st.dataframe(metrics, use_container_width=True)
        metric_columns = [
            column
            for column in ["precision", "recall", "f1", "pr_auc"]
            if column in metrics.columns
        ]
        if metric_columns:
            st.subheader("So sánh metric mô hình")
            st.bar_chart(metrics.set_index("model")[metric_columns], y_label="Điểm")

        matrix_columns = st.columns(3)
        for column, filename, title in zip(
            matrix_columns,
            [
                "logistic_regression_confusion_matrix.png",
                "random_forest_confusion_matrix.png",
                "random_forest_behavioral_confusion_matrix.png",
            ],
            ["Logistic Regression", "Random Forest", "Random Forest Behavioral"],
        ):
            image_path = report_dir / filename
            if image_path.exists():
                with column:
                    st.subheader(title)
                    st.image(str(image_path), use_container_width=True)
        st.caption(
            "Metric mô tả lần đánh giá đã lưu; không phải kết quả đánh giá trên file "
            "vừa tải lên. Anomaly score là điểm của model, không mặc định đã calibration."
        )
    else:
        st.info("Chưa có model_metrics.csv trong reports/ml.")
