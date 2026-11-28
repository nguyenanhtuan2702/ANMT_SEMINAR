# Đánh giá — Ngọc

## EDA

Mở `evaluation/eda.ipynb` trong VS Code/Jupyter và chạy toàn bộ notebook từ
thư mục gốc project. Notebook đọc `data/processed/normalized_logs.csv`, sinh biểu
đồ trực tiếp từ dữ liệu và lưu ảnh vào `reports/eda/`. Không cần ảnh đầu vào
được tạo sẵn.

EDA xem schema, missing/duplicate, nhãn, Activity, phân bố theo thời gian,
feature ứng viên, nguy cơ leakage và tỷ lệ nhãn trên temporal split.

Huấn luyện từ bundle chuẩn hóa ở `data/processed/`:

```powershell
.\.venv\Scripts\python.exe -m models.train_model
```

Script dùng `normalized_logs.csv`, chia tuần tự thành 64% train, 16%
validation và 20% test, chọn threshold trên validation, lưu pipeline vào
`models/artifacts/` và ghi metric, confusion matrix, FP/FN cùng manifest vào
`reports/ml/`. Fit preprocessing chỉ trên train; không dùng `Anomaly` làm
feature. Báo cáo metric kèm tỷ lệ nhãn từng split và kiểm tra drift.
