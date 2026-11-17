# Quy ước tích hợp — đề xuất để nhóm chốt

Đây là bản đề xuất, chưa phải API đã được cả nhóm xác nhận.

- Normalizer nhận CSV và trả DataFrame; Timestamp kiểu datetime; giữ log gốc.
- Có `source_row_id` ổn định và duy nhất trong mỗi file. Kiểm tra `id` trước khi dùng làm khóa; không tự giả định id duy nhất.
- ML nhận dữ liệu chuẩn hóa và trả source_row_id, predicted_label, anomaly_score. Không yêu cầu Anomaly khi inference. Ngọc cần mô tả rõ ý nghĩa và miền giá trị score.
- Rule Engine trả alert có timestamp, user, agent, activity, rule_id, reason, severity, source_row_id. Một sự kiện có thể có nhiều cảnh báo.
- Correlation trả nhóm sự kiện và các source_row_id liên quan, có thứ tự thời gian; chỉ dùng hiện tại/quá khứ.
- Severity dùng LOW/MEDIUM/HIGH/CRITICAL và kèm lý do. Nhóm chốt ai gọi bước này và cách phối hợp kết quả ML/rule.
- Dashboard gọi module, không tự viết lại luật hoặc huấn luyện mô hình.
- Anomaly là nhãn tham chiếu để đánh giá; không được dùng như đầu ra phát hiện hoặc feature ML.
- Không có cảnh báo và chưa chạy detector là hai trạng thái riêng biệt.

## Cần chốt trong buổi họp
1. Vai trò Tuấn/Thọ theo Excel hay PDF.
2. Tên hàm, kiểu dữ liệu, cột đầu ra, khóa nối và cách báo lỗi.
3. Phiên bản Python/thư viện chung và ngày bàn giao mẫu đầu ra.
4. Ngày ghép module thật, để lại ít nhất 2–3 ngày trước hạn cho kiểm thử/báo cáo.
