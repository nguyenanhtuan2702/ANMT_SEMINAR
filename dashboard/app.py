"""Tuấn: giao diện khởi đầu. Chưa tích hợp bộ phát hiện."""
import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI Security Log Analyzer", layout="wide")
st.title("AI Security Log Analyzer")
st.caption("Đồ án An ninh máy tính • SPEDIA • Khung giao diện ban đầu")
file = st.sidebar.file_uploader("Tải nhật ký CSV", type=["csv"])
overview, events, alerts, evaluation = st.tabs(
    ["Tổng quan", "Sự kiện", "Cảnh báo", "Đánh giá ML"]
)
with alerts:
    st.info("Chưa tích hợp Rule Engine và ML. Chưa có kết quả phát hiện.")
with evaluation:
    st.info("Chờ bảng đánh giá trên tập test và biểu đồ từ Ngọc.")
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
required = {"Timestamp", "User", "Agent_name", "Activity", "Action"}
missing = required - set(df.columns)
if missing:
    st.error("Thiếu cột: " + ", ".join(sorted(missing)))
    st.stop()
with overview:
    a, b, c = st.columns(3)
    a.metric("Số sự kiện", f"{len(df):,}")
    b.metric("Người dùng có tên", df["User"].nunique())
    c.metric("Máy/agent", df["Agent_name"].nunique())
    st.subheader("Sự kiện theo loại hoạt động")
    st.bar_chart(df["Activity"].fillna("Không có thông tin").value_counts())
    st.caption("Đang xem dữ liệu gốc; module chuẩn hóa của Thọ sẽ được tích hợp sau.")
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
