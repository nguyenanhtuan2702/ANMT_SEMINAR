# Phân công kỹ thuật

Nguồn thống nhất hiện hành là [Tài liệu thống nhất kỹ thuật về tích hợp ML–Dashboard](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md), lập ngày 27/11/2026. Bảng dưới đây thay ghi chú phân công ban đầu và phản ánh phạm vi từng người trong đợt tích hợp.

| Người phụ trách | Công việc | Vị trí chính |
|---|---|---|
| **Thọ** | Xác nhận `source_row_id`, normalized event schema và alert schema; hỗ trợ kiểm tra join; bảo đảm Rule pipeline/Severity không đổi ngoài phạm vi. | `preprocessing/`, `detection/pipeline.py`, `detection/severity.py`, hợp đồng tích hợp |
| **Ngọc** | Sửa ML Engine để giữ khóa chuẩn; xác nhận class 1 = Anomaly, score và threshold; bổ sung test; cung cấp quy trình tái lập training/model metadata. | `detection/ml_engine.py`, `models/`, `reports/ml/`, `tests/test_ml_engine.py` |
| **Tuấn** | Nối inference vào Dashboard; thêm model selector, threshold, prediction/score, bộ lọc, so sánh Rule-vs-ML, cache và xử lý lỗi; cập nhật hướng dẫn. | `dashboard/service.py`, `dashboard/views.py`, `README.md`, `tests/` |
| **Cả nhóm** | Chạy regression và end-to-end trên cùng dataset/môi trường; xác nhận các tiêu chí INT-01–INT-17. | Toàn repository |

## Hiện trạng

- Giai đoạn 1 Rule-based của Thọ đã được Tuấn nghiệm thu ngày 27/11/2026; điều đó chưa phải nghiệm thu tích hợp ML.
- ML Engine có `predict()`, nhưng `make_source_row_ids()` hiện dùng `id` khi duy nhất hoặc fallback `row_N`; cần sửa trước khi join với normalized events.
- Dashboard hiện chỉ gọi Loader → Normalizer → Rule pipeline. Các control/model comparison ML trong bảng phân công là đầu việc, chưa phải chức năng đã có.
- Ba model artifacts hiện có trong workspace, nhưng `models/artifacts/*` bị Git ignore; bản clone từ GitHub có thể cần nhận chúng riêng.
- `models/train_model.py` hiện chỉ có docstring; Ngọc cần bàn giao script huấn luyện tái lập hoặc tài liệu tái lập đầy đủ.

Tiêu chí chi tiết và checklist trước khi merge nằm trong tài liệu thống nhất kỹ thuật.
