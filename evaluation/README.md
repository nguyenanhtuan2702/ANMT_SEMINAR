# Đánh giá — Ngọc
Lưu notebook/script, bảng metric và confusion matrix thực tế. Chia train/test theo thời gian; fit preprocessing trên train. Không điền số liệu minh họa thành kết quả thực nghiệm.

## Kiểm chứng rule Task 5

`rule_metrics.py` tính TP/FP/FN/TN, precision, recall và F1 theo source_row_id duy nhất; union không cộng trùng. `Anomaly` chỉ được dùng ở đây để chấm nhãn, không đưa ngược vào detector. Recall dùng toàn bộ event nhãn 1 làm mẫu số; nhãn thiếu/lạ bị loại và đếm riêng. Chỉ số không xác định được để trống, không tự điền 0/1.

Task 5 là đánh giá mô tả trên full dataset đã khảo sát, **chưa phải holdout test**; giữ đề xuất chia thời gian cho thực nghiệm ML/đánh giá độc lập sau này.

Workflow có thể chạy lại vào thư mục mới:

```powershell
python -m evaluation.verify_rules --phase prepare --output reports/rule_validation_recheck
python -m evaluation.task5_review_annotations --folder reports/rule_validation_recheck
python -m evaluation.verify_rules --phase evaluate --output reports/rule_validation_recheck
```

prepare chạy detector không nhãn, lấy 25 mẫu/rule theo hash/seed cố định, đối chiếu raw trực tiếp CSV. Auth chỉ có 8 alert nên lấy cả 8. Rule disabled được chạy riêng chẩn đoán. Module annotations tái tạo nhận xét kỹ thuật Codex hỗ trợ dựa trên các mẫu raw/argv đã đọc trong Task 5; đó không phải review người độc lập hoặc nhãn ground truth. Khi đổi dữ liệu, cần review lại và cập nhật notes, không mặc định coi annotation template là kết luận chuyên gia.

Pha evaluate chỉ chạy sau khi notes phủ đúng toàn bộ mẫu, kiểm tra hash nguồn/config/output/sample. Sau đánh giá, prepare từ chối ghi đè cùng thư mục; notes đã chấm cũng không được thay ngầm. Muốn chỉ tái tính metric với snapshot không đổi:

```powershell
python -m evaluation.verify_rules --phase evaluate
```

Đầu ra `reports/rule_validation/`: rule_metrics.csv, diagnostic_rule_metrics.csv, task4_baseline_metrics.csv, sample_review.csv, reviewed_samples.json, tp_fp_examples.json, merged_alerts_v1.0.json/csv, snapshot config và các manifest. Technical suspected FP khác FP theo Anomaly; ví dụ TP/FP không có trong dữ liệu được ghi null, không tạo giả.
