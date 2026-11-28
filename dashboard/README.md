# Streamlit dashboard

Hướng dẫn cài dependencies, chuẩn bị model artifacts và chạy ứng dụng nằm tại
[README gốc](../README.md).

Entry point là `dashboard/app.py`. `dashboard.service.run_upload_pipeline()`
thực hiện loader → normalizer → Rule pipeline và giữ DataFrame chuẩn hóa để
inference. Giao diện gọi ML riêng trên toàn bộ event, dùng `source_row_id` để
ghép kết quả; ML không tham gia rule, correlation, severity hay alert schema
v1.0.

## Luồng Dashboard

- Rule pipeline được cache theo byte CSV cùng hash cấu hình Rule và Severity.
- ML có cache riêng theo hash nội dung file, DataFrame chuẩn hóa, model,
  threshold và phiên bản artifact. Đổi model/threshold không làm chạy lại Rule
pipeline.
- Threshold mặc định được đọc theo model trong
  `reports/ml/model_thresholds.json`. Mục bị thiếu/sai hoặc file không đọc được
  dùng fallback `0.52` và hiện thông báo.
- Events hỗ trợ lọc theo Activity, User, Agent và nhóm so sánh. Các bộ lọc chỉ
  đổi nội dung đang xem, không đổi tập dữ liệu inference.
- ML evaluation đếm Both, Rule Only, ML Only và Neither trên các event đã có
  prediction. Các event thiếu kết quả luôn là `Not Evaluated`.
- Lỗi ML được báo riêng; Overview, Events, Alerts và Timeline của Rule vẫn sử
  dụng được. Không suy diễn nhóm Rule Only/ML Only thành lỗi phát hiện.

Xem [hợp đồng pipeline](../docs/PIPELINE_API.md), [hợp đồng tích hợp](../docs/INTEGRATION_CONTRACT.md)
và [tài liệu thống nhất kỹ thuật](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md)
để biết schema, khóa nguồn, Severity và các giới hạn tích hợp.
