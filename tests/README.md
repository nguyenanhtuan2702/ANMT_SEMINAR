# Kiểm thử

Cài dependencies phát triển từ thư mục gốc bằng `pip install -r requirements-dev.txt`,
sau đó chạy `python -m unittest discover -s tests -v`.

Unit tests bao phủ loader, normalizer, Rule Engine, correlation, severity, alert merge,
pipeline và dashboard. `pytest` cần cho `test_task9_boundaries.py`; `joblib` được cài
cùng dependencies runtime để các test ML có thể import. Script `validate_*_dataset.py`
dùng riêng để kiểm chứng dataset đầy đủ.

Các test hiện có chưa chứng nhận hợp đồng ML mới: cần bổ sung kiểm tra giữ nguyên
`source_row_id`, class 1 = Anomaly, join one-to-one, threshold/model cache, so sánh
Rule-vs-ML và xử lý lỗi theo [tiêu chí INT-01–INT-17](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md).
