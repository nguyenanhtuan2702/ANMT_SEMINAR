# Streamlit dashboard

Hướng dẫn cài đặt và chạy thống nhất tại [README gốc](../README.md).

Entry point: `dashboard/app.py`. `service.py` gọi loader → normalize → pipeline rule-based; `views.py` hiển thị Overview, Events, Alerts, Timeline và trạng thái ML.

**Hiện trạng:** Dashboard chưa gọi `detection.ml_engine.predict()`. Tab ML evaluation báo ML chưa chạy; model selector, threshold slider, cột prediction/score và so sánh Rule-vs-ML chưa được triển khai.

**Hướng đã thống nhất:** tích hợp ML sau normalize, join bằng `source_row_id`, giữ kết quả Rule/Severity độc lập và xử lý lỗi ML riêng. Chi tiết cùng tiêu chí nghiệm thu ở [tài liệu thống nhất kỹ thuật](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md).

Luồng Rule-based hiện tại ở [PIPELINE_API.md](../docs/PIPELINE_API.md); hợp đồng module và khóa nguồn ở [INTEGRATION_CONTRACT.md](../docs/INTEGRATION_CONTRACT.md).
