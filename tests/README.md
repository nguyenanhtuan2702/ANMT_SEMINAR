# Kiểm thử

Cài dependencies phát triển từ thư mục gốc bằng `pip install -r requirements-dev.txt`,
sau đó chạy cả hai bộ:

```powershell
python -m unittest discover -s tests -v
python -m pytest -q
```

`unittest` bao phủ loader, normalizer, Rule Engine, correlation, severity, alert merge,
pipeline, Dashboard, ML engine và Dashboard Service. `test_task9_boundaries.py` dùng
các hàm test kiểu pytest, nên `unittest discover` không tính chúng; chạy pytest để
đưa các kiểm tra ranh giới và tái lập Task 9 vào lượt kiểm thử.

`test_analysis_pipeline.py` kiểm tra API hiện tại `run_detection_pipeline()` và các
module thành phần; không có API `analyze_events()` trong `detection.pipeline`.
Threshold test mock `_load_pipeline`, tức đúng biên cache model, để model thật được
cache ở test trước không thể thay thế mock xác suất. `test_dashboard_service.py` có
test integration chạy artifact thật khi `scikit-learn` và artifact sẵn có. Script
`validate_*_dataset.py` dùng riêng để kiểm chứng dataset đầy đủ.

Hai test `full_dataset` của Task 9 đọc CSV gốc tại
`data/raw/logs_SPEDIA_annotated_en.csv`; nếu thiếu, pytest sẽ skip riêng hai ca
này. Các kiểm tra khác vẫn chạy bình thường.
