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
    activities = sorted(df["Activity"].dropna().astype(str).unique())
    selected = st.multiselect("Lọc loại hoạt động", activities)
    view = df[df["Activity"].isin(selected)] if selected else df
    st.write(f"Có {len(view):,} sự kiện phù hợp. Hiển thị tối đa 1.000 dòng đầu.")
    st.dataframe(view.head(1000), use_container_width=True)
    if "Anomaly" in df.columns:
        st.caption("Anomaly là nhãn có sẵn trong dataset, không phải dự đoán của ứng dụng.")
