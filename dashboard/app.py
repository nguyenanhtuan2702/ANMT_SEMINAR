"""Streamlit dashboard for AI Security Log Analyzer."""
from pathlib import Path

import pandas as pd
import streamlit as st

from detection.ml_engine import predict as ml_predict

st.set_page_config(page_title="AI Security Log Analyzer", layout="wide")
st.title("AI Security Log Analyzer")
st.caption("Phân tích nhật ký và cảnh báo bất thường bằng Machine Learning")
file = st.sidebar.file_uploader("Tải nhật ký CSV", type=["csv"])
model_name = st.sidebar.selectbox(
    "Mô hình ML",
    options=[
        "random_forest_behavioral.joblib",
        "random_forest.joblib",
        "logistic_regression.joblib",
    ],
)
threshold = st.sidebar.slider(
    "Ngưỡng anomaly",
    min_value=0.05,
    max_value=0.95,
    value=0.52,
    step=0.01,
)
overview, events, alerts, evaluation = st.tabs(
    ["Tổng quan", "Sự kiện", "Cảnh báo", "Đánh giá ML"]
)
if file is None:
    with overview:
        st.info("Chọn file logs_SPEDIA_annotated_en.csv ở thanh bên để bắt đầu.")
    st.stop()
try:
    df = pd.read_csv(file)
except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError, ValueError) as error:
    st.error(f"Không đọc được CSV: {error}")
    st.stop()
if df.empty:
    st.warning("File không có bản ghi.")
    st.stop()
required = {"Timestamp", "User", "Agent_name", "Activity", "Action", "Decoder_name"}
missing = required - set(df.columns)
if missing:
    st.error("Thiếu cột: " + ", ".join(sorted(missing)))
    st.stop()
try:
    with st.spinner(f"Đang phân tích {len(df):,} sự kiện bằng {model_name}..."):
        ml_result = ml_predict(df, model_name=model_name, threshold=threshold)
except (ValueError, FileNotFoundError) as error:
    st.error(f"Không chạy được ML inference: {error}")
    st.stop()
st.sidebar.success(f"Đã nạp {file.name} • {len(df):,} sự kiện")

alert_count = int(ml_result["predicted_label"].sum())
with alerts:
    st.subheader("Cảnh báo do mô hình ML")
    a, b, c = st.columns(3)
    a.metric("Số cảnh báo", f"{alert_count:,}")
    b.metric("Ngưỡng", f"{threshold:.2f}")
    c.metric("Tỉ lệ cảnh báo", f"{alert_count / len(ml_result):.2%}")

    alert_view = ml_result[
        ml_result["predicted_label"] == 1
    ].sort_values(["timestamp", "anomaly_score"], ascending=[True, False])

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.subheader("Cảnh báo theo hoạt động")
        if alert_view.empty:
            st.bar_chart(pd.Series(dtype="int64", name="Số cảnh báo"))
        else:
            st.bar_chart(
                alert_view["activity"].fillna("Không có thông tin").value_counts(),
                y_label="Số cảnh báo",
            )

    with chart_right:
        st.subheader("Cảnh báo theo ngày")
        daily_alerts = (
            alert_view.assign(date=alert_view["timestamp"].dt.floor("D"))
            .groupby("date")
            .size()
            .rename("Số cảnh báo")
        )
        st.line_chart(daily_alerts, y_label="Số cảnh báo")

    st.subheader("Phân bố anomaly score")
    score_labels = [
        f"{start / 10:.1f}–{(start + 1) / 10:.1f}"
        for start in range(10)
    ]
    score_bins = pd.cut(
        ml_result["anomaly_score"],
        bins=[i / 10 for i in range(11)],
        labels=score_labels,
        include_lowest=True,
    )
    score_distribution = score_bins.value_counts(sort=False)
    score_distribution.index = score_distribution.index.astype(str)
    score_distribution = score_distribution.rename("Số sự kiện")
    st.bar_chart(score_distribution, y_label="Số sự kiện")

    if alert_view.empty:
        st.success("Không có cảnh báo vượt ngưỡng hiện tại.")
    else:
        st.subheader("Danh sách cảnh báo")
        st.dataframe(alert_view, use_container_width=True)

with evaluation:
    st.subheader("Kết quả thực nghiệm đã lưu")
    metric_path = Path(__file__).resolve().parents[1] / "reports" / "ml" / "model_metrics.csv"
    if metric_path.exists():
        metrics = pd.read_csv(metric_path)
        st.dataframe(metrics, use_container_width=True)
        chart_metrics = [
            column
            for column in ["precision", "recall", "f1", "pr_auc"]
            if column in metrics.columns
        ]
        if chart_metrics:
            st.subheader("So sánh metric mô hình")
            st.bar_chart(metrics.set_index("model")[chart_metrics], y_label="Điểm")

        report_dir = Path(__file__).resolve().parents[1] / "reports" / "ml"
        image_left, image_right = st.columns(2)
        for column, filename, title in [
            (image_left, "logistic_regression_confusion_matrix.png", "Logistic Regression"),
            (image_right, "random_forest_confusion_matrix.png", "Random Forest"),
        ]:
            image_path = report_dir / filename
            if image_path.exists():
                with column:
                    st.subheader(f"Confusion matrix — {title}")
                    st.image(str(image_path), use_container_width=True)
    else:
        st.info("Chưa có model_metrics.csv trong reports/ml.")
with overview:
    a, b, c = st.columns(3)
    a.metric("Số sự kiện", f"{len(df):,}")
    b.metric("Người dùng có tên", df["User"].nunique())
    c.metric("Máy/agent", df["Agent_name"].nunique())
    d, e = st.columns(2)
    d.metric("Cảnh báo ML", f"{alert_count:,}")
    e.metric("Tỉ lệ cảnh báo", f"{alert_count / len(ml_result):.2%}")

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.subheader("Sự kiện theo loại hoạt động")
        st.bar_chart(
            df["Activity"].fillna("Không có thông tin").value_counts(),
            y_label="Số sự kiện",
        )
    with chart_right:
        st.subheader("Sự kiện theo thời gian")
        daily_events = (
            df.assign(_date=pd.to_datetime(df["Timestamp"]).dt.floor("D"))
            .groupby("_date")
            .size()
            .rename("Số sự kiện")
        )
        st.line_chart(daily_events, y_label="Số sự kiện")

    if "Anomaly" in df.columns:
        st.subheader("Nhãn tham chiếu trong CSV")
        st.caption("Đây là nhãn có sẵn trong dữ liệu, không phải dự đoán của mô hình.")
        st.bar_chart(
            df["Anomaly"].value_counts().sort_index().rename(index={0: "Bình thường", 1: "Anomaly"}),
            y_label="Số sự kiện",
        )
with events:
    st.subheader("Danh sách sự kiện")

    col1, col2, col3 = st.columns(3)

    with col1:
        selected_activities = st.multiselect(
            "Loại hoạt động",
            options=sorted(
                df["Activity"].dropna().astype(str).unique()
            ),
        )

    with col2:
        selected_users = st.multiselect(
            "Người dùng",
            options=sorted(
                df["User"].dropna().astype(str).unique()
            ),
        )

    with col3:
        selected_agents = st.multiselect(
            "Máy / Agent",
            options=sorted(
                df["Agent_name"].dropna().astype(str).unique()
            ),
        )

    include_missing_users = st.checkbox(
        "Giữ các sự kiện thiếu tên người dùng khi lọc User",
        value=False,
    )

    # Không chọn giá trị nào nghĩa là không lọc trường đó.
    view = df.copy()

    if selected_activities:
        view = view[
            view["Activity"].astype("string").isin(selected_activities)
        ]

    if selected_users:
        user_mask = (
            view["User"].astype("string").isin(selected_users)
        )

        if include_missing_users:
            user_mask = user_mask | view["User"].isna()

        view = view[user_mask]

    if selected_agents:
        view = view[
            view["Agent_name"].astype("string").isin(selected_agents)
        ]

    st.caption(
        "Các bộ lọc kết hợp đồng thời. "
        "Để trống một bộ lọc để lấy tất cả giá trị của trường đó. "
        "Bộ lọc hiện chỉ áp dụng cho tab Sự kiện."
    )

    st.write(
        f"Có {len(view):,} / {len(df):,} sự kiện phù hợp."
    )

    if view.empty:
        st.info(
            "Không có sự kiện phù hợp. "
            "Hãy bỏ bớt hoặc thay đổi điều kiện lọc."
        )
    else:
        st.caption("Hiển thị tối đa 1.000 dòng đầu.")
        st.dataframe(
            view.head(1000),
            use_container_width=True,
        )

    if "Anomaly" in df.columns:
        st.caption(
            "Anomaly là nhãn tham chiếu có sẵn trong dataset, "
            "không phải dự đoán của ứng dụng."
        )
