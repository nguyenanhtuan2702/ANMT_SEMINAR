# Hợp đồng tích hợp đã triển khai

Luồng ứng dụng:

`CSV bytes → load_log_csv → normalize_logs → ML + Rule Engine → correlate_events → assign_severity → Streamlit`

`Anomaly` là nhãn tham chiếu tùy chọn; không dùng làm feature, rule input hoặc severity signal.

## Module và hợp đồng

| Module | API | Hành vi |
|---|---|---|
| Loader | `load_log_csv(source)` | Đọc path/bytes/stream; xác thực CSV không rỗng và sáu trường nền `Timestamp`, `User`, `Agent_name`, `Activity`, `Action`, `Decoder_name`; tạo `source_row_id` theo SHA-256 nội dung file và thứ tự record nếu chưa có; từ chối ID trùng/thiếu. |
| Normalizer | `normalize_logs(frame)` | Yêu cầu `source_row_id` hợp lệ do Loader cung cấp; giữ nguyên ID, từ chối ID thiếu/rỗng/trùng. Trả bản sao; giữ cột raw, tạo timestamp `datetime64[ns]`, đánh dấu timestamp lỗi, strip/casefold trường phân loại và tạo hour/day/date. Không loại dòng lỗi thời gian. |
| ML | `predict(df, model_name, threshold)` | Trả source ID, timestamp, actor, activity/action, predicted label và anomaly score. Chỉ chấm các event có Timestamp hợp lệ; không yêu cầu `Anomaly`. |
| Rule Engine | `run_rules(events)` | Cần thêm `Command`, `Path`, `Full_log`, `Description`, `Url`; trả mỗi cặp event/rule thành một alert có rule ID, reason, severity gốc, evidence và source ID. |
| Correlation | `correlate_events(events, alerts)` | Trả events có `group_id` và bảng timeline. Nhóm theo User + Agent, fixed 900-second epoch-aligned window; tách nếu gap giữa hai event >300 giây. Thiếu actor/time thì không nhóm. |
| Severity | `assign_severity(events, alerts)` | Nhận alert Rule Engine và ML; thêm `base_severity`, `severity`, `severity_reason`. Mỗi quyết định chỉ xét event hiện tại và prefix thời gian trước nó. |
| Orchestrator | `analyze_events(input_events, model_name, threshold)` | Trả normalized/correlated events, ML predictions, alert theo nguồn, alerts hợp nhất, event groups và diagnostics. |
| Dashboard | `dashboard/app.py` | Chỉ gọi orchestrator và trình bày dữ liệu; không triển khai lại detector. |

## Rule đang bật

- `CMD_NMAP`, `CMD_JOHN`, `CMD_MSFCONSOLE`: Action là `command executed` và basename của Command khớp chính xác tên executable.
- `FILE_CONFIG_CHANGE`: Action là file modified/added/deleted và Path nằm trong nhóm cấu hình đã định nghĩa. Với modified, không cảnh báo nếu raw log xác nhận chỉ đổi mtime/ctime.
- `HTTP_IP_HOST`: Action là URL accessed/accedida và URL HTTP(S) có hostname là IP literal hợp lệ.
- `AUTH_FAILURE_WINDOW`: chỉ nhận tín hiệu login failure rõ trong Action/Description/Full_log; ít nhất ba failure của cùng User + Agent trong cửa sổ đóng 300 giây. Thiếu User thì bỏ qua rule này.
- `CMD_NETCAT` không bật mặc định.

Chi tiết rule, giới hạn và bằng chứng dataset nằm trong `data/processed/DATA.md`. Có rule hit không đồng nghĩa đã xác minh một cuộc tấn công.

## Severity policy

- Alert ML đơn lẻ: LOW.
- Một rule: dùng mức gốc của rule (`HTTP_IP_HOST` LOW; các rule còn lại MEDIUM).
- HIGH: nhiều loại rule trên cùng event, ML cùng rule trên cùng event, hoặc prefix cùng group đã có ít nhất ba event rule-alert / ít nhất hai loại rule.
- CRITICAL: prefix có ít nhất 10 event rule-alert, ít nhất ba loại rule và có ML alert corroboration.
- Score cao một mình không nâng severity. Severity là mức ưu tiên rà soát, không phải kết luận tác động.
- Severity ở bảng realtime dùng policy này; các file prioritized có sẵn trong `data/processed/` là snapshot được tạo theo policy severity riêng mô tả trong `data/processed/DATA.md`, nên phân phối mức có thể khác.

## Trạng thái khi không có kết quả

- Detector chạy và không có alert: danh sách rỗng.
- Detector không chạy được do thiếu cột/model: raise lỗi và dashboard hiển thị thông báo.
- Event có Timestamp lỗi được giữ ở tab Sự kiện, nhưng không được dự đoán/correlate.
- Alert không có group vẫn được giữ trong bảng cảnh báo; correlation không loại alert.
