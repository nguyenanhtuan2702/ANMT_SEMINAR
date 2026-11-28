# Alert schema v1.0 — bàn giao tích hợp

Ngày đóng băng kỹ thuật: **21/11/2026**. Trạng thái xác nhận Tuấn: **đang chờ**, chưa có trao đổi/xác nhận được cung cấp. Đây là giao diện đã triển khai và kiểm thử để review; không phải biên bản Tuấn đã đồng ý.

Nguồn chuẩn máy đọc: `docs/schemas/alert_v1.0.schema.json`. Hash khóa phiên bản nằm trong `docs/schemas/alert_v1.0.freeze.json`, được kiểm tra bằng test. Thay field/kiểu/ngữ nghĩa phá vỡ tương thích phải phát hành phiên bản mới, không sửa ngầm v1.0.

## Hai lớp alert

1. Atomic alert của `detect_rules`: giữ nguyên 11 field Task 4, một record cho mỗi source_row_id/rule_id. Kiểu dây truyền đã có base severity, không null; `Alert` TypedDict lịch sử vẫn cho phép None ở các bước chưa phân loại, nhưng chúng không được xuất theo wire v1.0.
2. Event alert của `merge_alerts`: **một record cho mỗi source_row_id**, dùng cho danh sách dashboard. Giữ mọi rule, reason và evidence bên trong rule_matches. Không đổi API atomic để tránh làm hỏng module đang tích hợp.

## Event alert — 12 field bắt buộc

| Field | Kiểu | Quy tắc |
|---|---|---|
| schema_version | string | Luôn `1.0` |
| alert_id | string | `<source_row_id>:merged:v1.0` |
| source_row_id | string | `<64 hex SHA-256 file>:<record_index đệm ít nhất 8 số>`; không đổi khi sort/merge |
| timestamp | string | ISO `YYYY-MM-DDTHH:MM:SS.mmm`, không tự gắn timezone |
| user | string hoặc null | User chuẩn hóa; không tạo `unknown` thay null |
| agent | string | Agent chuẩn hóa, không rỗng |
| activity | string | Ngữ cảnh sự kiện, không phải kết luận tấn công |
| rule_ids | list[string] | Không rỗng, duy nhất, sort theo tên rule |
| rule_matches | list[object] | Cùng thứ tự/số phần tử với rule_ids; đầy đủ từng kết quả rule |
| reason | string | Ghép theo thứ tự rule_ids: `RULE: reason` ngăn bằng ` | ` |
| severity | enum | LOW/MEDIUM/HIGH/CRITICAL; lấy mức ưu tiên cao nhất của các rule tại bước xuất: base ở Task 5, mức sau chấm ngữ cảnh ở bảng prioritized/pipeline Task 7/8 |
| severity_reason | string | Nêu quy tắc lấy max; không khẳng định tác động |

Mỗi rule_match có đúng 6 field: alert_id, rule_id, reason, evidence, severity, severity_reason. Atomic alert thêm 5 field source_row_id, timestamp, user, agent, activity để thành 11 field.

Evidence là map string -> string/null, giữ nguyên giá trị raw; không chứa Anomaly/Level. Danh sách/schema hợp đồng cũng không có nhãn đánh giá. Nhãn và TP/FP chỉ tồn tại ở artifact evaluation, không ghép ngược vào alert dùng cho phát hiện.

## Quy tắc gộp và kiểm tra

- Gộp theo **source_row_id**, không theo raw text, User hay timestamp. Khác source_row_id thì giữ hai event dù raw giống hệt.
- Cùng source_row_id/rule_id và toàn bộ nội dung giống nhau: loại bản gửi lặp chính xác. Nếu nội dung khác, báo ValueError; không lấy đại bản đầu/cuối.
- Các rule cùng một event phải thống nhất timestamp/user/agent/activity; khác thì báo lỗi dữ liệu.
- Mức ưu tiên max theo LOW < MEDIUM < HIGH < CRITICAL. Không cộng điểm chỉ vì trùng nhiều rule, không đọc nhãn. Đây là max base severity, chưa phải điểm correlation/ML hoặc tác động đã xác minh.
- Hàm không sửa list/evidence đầu vào; output ổn định khi đảo thứ tự và thêm bản gửi lặp.
- JSON Schema kiểm tra hình dạng/kiểu; `validate_atomic_alert` và `validate_merged_alert` kiểm tra thêm lịch, khóa liên quan, thứ tự rule_ids/rule_matches, nội dung reason và priority max. Dùng cả quy tắc nghiệp vụ này khi tích hợp.

## API bàn giao

```python
from detection.rule_engine import detect_rules, alerts_to_dataframe
from detection.alert_aggregation import (
    merge_alerts, merged_alerts_to_dataframe, validate_merged_alert,
)

atomic_alerts = detect_rules(events)
event_alerts = merge_alerts(atomic_alerts)
table = merged_alerts_to_dataframe(event_alerts)
```

DataFrame event có đúng 12 cột ngay cả khi rỗng. rule_ids/rule_matches là list trong bộ nhớ; khi ghi CSV Task 5, hai field được serialize JSON, caller đọc CSV phải json.loads để lấy lại list. JSON v1.0 giữ user=null, không dùng chuỗi `null`.

Ví dụ thật: `reports/rule_validation/merged_alerts_v1.0.json` và `.csv`. Không có nhãn trong hai file này. Dataset hiện không có event khớp nhiều rule mặc định, nên số event sau merge bằng atomic; ca nhiều rule và gửi lặp được xác minh bằng unit test.

## Nội dung Tuấn cần xác nhận

- Dashboard dùng event alert để hiển thị một dòng/sự kiện, mở rule_matches khi xem chi tiết; atomic alert vẫn dùng cho thống kê từng rule.
- Tuân theo null user, timezone chưa xác định, list JSON và trạng thái detector error/not_run/success.
- Đồng ý giữ field/kiểu v1.0 và cơ chế phiên bản mới khi đổi; phân biệt max base priority với kết quả module severity ở task sau.

Chỉ cập nhật team_signoff khi có xác nhận thật kèm người/ngày/bằng chứng trao đổi. Chưa gửi tin nhắn, không giả lập chữ ký hoặc xác nhận của Tuấn.

## Artifact dùng chung sau rà soát Task 4–6

`data/alerts.csv` là bản merged v1.0 chính; `data/alerts_atomic.csv` giữ atomic 11 field. Đọc bằng `read_alerts()` hoặc `read_atomic_alerts()` từ `detection.shared_output_io`, chuyển kèm sidecar `.schema.json` để khôi phục list/dict, null và kiểm tra checksum. Cả hai bảng hiện có 1.301 dòng, khớp snapshot Task 5 đã đóng băng. Không thay đổi JSON schema/freeze; xác nhận Tuấn còn pending. Xem [SHARED_OUTPUTS.md](SHARED_OUTPUTS.md).
