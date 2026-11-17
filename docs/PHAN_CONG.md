# Phân công ban đầu
Căn cứ: bảng Excel Phan_cong_do_an_ANMT.xlsx.
PDF hướng dẫn đang ghi ngược vai trò Tuấn/Thọ; nhóm cần xác nhận trong buổi họp.

| Người | Phần phụ trách | Vị trí |
|---|---|---|
| Tuấn | Dashboard, tích hợp, hướng dẫn chạy, demo | dashboard/, README.md, docs/ |
| Thọ | Loader, normalizer, rules, correlation, severity | preprocessing/, detection/ (trừ ml_engine.py) |
| Ngọc | ML, huấn luyện, inference, đánh giá | models/, detection/ml_engine.py, evaluation/ |

Bộ khung chỉ có giao diện tải CSV, thống kê và bảng sự kiện chạy bằng Streamlit.
Các file xử lý và ML hiện là chỗ dành sẵn, chưa có thuật toán.
