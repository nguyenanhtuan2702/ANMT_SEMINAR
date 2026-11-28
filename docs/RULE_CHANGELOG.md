# Lịch sử kỹ thuật rule

## Task 4 — baseline

Cấu hình mặc định sinh 1.661 atomic alert: CMD_NMAP 47, CMD_JOHN 185, CMD_MSFCONSOLE 105, FILE_CONFIG_CHANGE 1.211, HTTP_IP_HOST 105, AUTH_FAILURE_WINDOW 8. CMD_NETCAT mặc định tắt. Hash cấu hình canonical được lưu trong `reports/rule_detection/rule_engine_validation.json`; giữ artifact Task 4 làm mốc lịch sử.

## Task 5 — thay đổi trước khi chấm nhãn

1. **So khớp tên executable Linux phân biệt hoa/thường.** Thêm `params.case_sensitive=true` cho command rule. Không đồng nhất NMAP và nmap. Hỗ trợ override false rõ ràng, mặc định true. Lý do là ngữ nghĩa tên executable trong raw audit Linux, không phải nhãn. Tập source_row_id/rule_id hiện có không đổi vì các tên khảo sát đều viết thường.
2. **Reason CMD_NMAP không khẳng định đã quét/chạy thành công.** Mẫu raw có ANOM_ABEND/Process ended abnormally; record_index 51627 còn có raw kiểu thống kê trung bình số log nhưng Command=nmap. Chỉ khẳng định trường Command khớp, yêu cầu đối chiếu nguồn/loại log. Không xóa riêng record 51627 hoặc thêm blacklist cho đúng một mẫu.
3. **Loại File modified có raw xác nhận chỉ đổi mtime/ctime.** Các mẫu 13155, 3914, 1804, 11826, 63430 và nhiều mẫu khác chỉ ghi `Changed attributes: mtime Old ...`; không chứng minh nội dung hoặc quyền thay đổi. Thêm `exclude_modified_raw_regex`, áp dụng riêng Action=file modified. Giữ added/deleted, thay hash/size/quyền/inode; không loại mọi `.txt`/`.bak`, không coi raw thiếu là bằng chứng chỉ đổi timestamp. Khi cấu hình bộ lọc thì Full_log là cột phụ thuộc. Kết quả kỹ thuật: loại 360 atomic file alert, FILE_CONFIG_CHANGE còn 851, tổng production còn 1.301. Không có alert mới; không dùng Anomaly để chọn bộ lọc.
4. **Giữ nguyên ngưỡng auth 3/300s, grouping User/Agent và trạng thái enabled.** Chưa có baseline vận hành/ủy quyền để chứng minh một ngưỡng khác tốt hơn. Không thử nhiều ngưỡng theo precision/recall, không thêm whitelist user/agent/IP theo nhãn. CMD_NETCAT vẫn chỉ được chạy riêng cho chẩn đoán, không nhập production union.

Thay đổi về regex không xóa dữ liệu hoặc sửa raw; chỉ thay điều kiện sinh alert. Timestamp tampering/timestomping có thể đáng quan tâm riêng: v1.0 chưa có rule cho nó, đây là giới hạn của việc giảm nhiễu cấu hình, không tuyên bố mtime-only luôn an toàn.

## Đóng băng để đánh giá

`reports/rule_validation/rules_frozen_v1.0.json` là snapshot cấu hình sau các sửa đổi kỹ thuật trên. `preparation_manifest.json` ghi SHA-256 file nguồn, config, atomic output và mẫu không nhãn. Pha evaluate kiểm tra lại hash và yêu cầu notes phủ đủ mẫu trước khi đọc nhãn để tính metric. Nếu thay rule sau lần đánh giá này, phải tạo phiên bản mới và đánh giá riêng; không sửa ngầm artifact v1.0.

Đóng băng schema tích hợp là quyết định kỹ thuật trên repo. Xác nhận Tuấn vẫn chờ, không có nội dung nào ở đây là biên bản đã được Tuấn đồng ý.
