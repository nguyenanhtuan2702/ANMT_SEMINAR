# Bàn giao dữ liệu Task 4–6

`data/alerts.csv` là bảng **sau gộp Task 5**, schema v1.0, một dòng trên `source_row_id`. Bảng nguyên tử Task 4 nằm riêng ở `data/alerts_atomic.csv`; không đổi schema một file theo bước chạy.

| File CSV | Số dòng trên dataset hiện tại | Cấu trúc |
|---|---:|---|
| `data/alerts_atomic.csv` | 1.301 | 11 cột atomic, gồm `rule_id`, `evidence` |
| `data/alerts.csv` | 1.301 | 12 cột merged v1.0, gồm `rule_ids`, `rule_matches` |
| `data/event_groups.csv` | 7.501 | 12 cột của `correlate()`, gồm danh sách event theo thời gian |

Hai bảng alert hiện có cùng số dòng vì dataset này không có event khớp nhiều rule đang bật. Logic merge vẫn giữ đầy đủ từng match khi có chồng lấp; các test dùng dữ liệu tổng hợp kiểm tra trường hợp đó.

Mỗi CSV phải đi cùng file cùng tên đuôi `.schema.json`. Sidecar ghi loại bảng, phiên bản, kiểu cột, null marker, checksum SHA-256, cấu hình và nguồn dữ liệu. `data/analysis_outputs.manifest.json` ghi hash của cả sáu file. Các artifact dữ liệu được ignore Git và có thể tạo lại; chuyển cả CSV và sidecar khi bàn giao cục bộ.

## Tạo lại

Chạy tại thư mục gốc repo sau khi đã xuất dataset chuẩn hóa ở Task 3:

```powershell
python -m detection.export_shared_outputs
```

Luồng: đọc `normalized_logs.csv` bằng reader Task 3 → bỏ `Anomaly` khỏi đầu vào detection/correlation → chạy cấu hình đã đóng băng → atomic → merge → correlate → xuất CSV/sidecar → đọc lại, so sánh chính xác và kiểm tra ba timeline demo. Không chấm nhãn hoặc chỉnh rule trong lệnh này. Script kiểm tra hash nguồn/rules với manifest Task 5, bảo vệ đầu vào chuẩn hóa và từ chối ghi đè file CSV chưa được định danh bằng sidecar cùng loại.

## Đọc cho dashboard và bước sau

```python
from preprocessing.normalized_io import read_normalized_logs
from detection.shared_output_io import (
    read_alerts, read_atomic_alerts, read_event_groups,
)
from detection.alert_aggregation import merged_alerts_to_dataframe
from detection.correlation import get_timeline

events = read_normalized_logs("data/normalized_logs.csv")
alerts = read_alerts()  # list[MergedAlert], rule_ids/rule_matches đã là list
alert_table = merged_alerts_to_dataframe(alerts)
groups = read_event_groups()  # DataFrame, datetime + Int64 + list/dict
atomic = read_atomic_alerts()  # tùy chọn, drill-down theo rule
timeline = get_timeline(events, groups.iloc[0]["group_id"], alerts)
```

`pd.read_csv` mặc định chỉ phù hợp xem bảng thô: các ô list/dict đang chứa JSON, không phải đối tượng Python. Các reader trên kiểm tra checksum, loại bảng, schema và invariant; phục hồi JSON, datetime, nullable integer và phân biệt null/chuỗi rỗng/chuỗi giống null. Thiếu sidecar, dùng sai reader hoặc CSV bị thay đổi sẽ báo lỗi rõ. Các hàm ghi `save_atomic_alerts`, `save_alerts`, `save_event_groups` nhận đối tượng tương ứng, đường dẫn CSV và `provenance` tùy chọn; trả metadata sidecar.

Join với `events` qua `source_row_id` để điều tra `Full_log`, `Description`, `Content`; không xóa/sửa raw hoặc tạo lại khóa từ file alert. `Anomaly` còn ở dataset nguồn chỉ dành cho đánh giá; không truyền nó vào rule/severity. Severity hiện là ưu tiên xử lý prototype. Correlation không tự kết luận tấn công hoặc nâng severity.

## Kiểm chứng và giới hạn

- `reports/shared_outputs/validation.json`: kiểm tra full 72.250 event, round-trip chính xác ba bảng, alert giống snapshot Task 5, nhóm giống nhau khi dùng atomic/merged sau đọc lại, ba timeline không đổi.
- 70.878 event được nhóm; 1.372 event thiếu User được báo riêng. Trong 1.301 event có alert, 1.131 có nhóm, 170 không có nhóm và vẫn nằm trong bảng alert.
- Cấu hình nhóm: fixed window 900 giây, gap 300 giây, min_events=1. `source_row_ids` giữ thứ tự Timestamp/record_index; summary live có thể tăng khi thêm tương lai. Để xem đúng snapshot quá khứ, dùng cùng `as_of=(Timestamp, record_index)` cho `correlate` và `get_timeline`.
- Bảng nhóm xuất là snapshot toàn dataset, không phải thông tin đã biết ở mọi thời điểm trước đó. Không dùng end_time/count toàn nhóm để làm đặc trưng inference tại một event cũ; phải tính snapshot nhân quả.
- Mẫu review, metric, ví dụ TP/FP và lịch sử thay đổi giữ tại `reports/rule_validation/`, `docs/RULE_CHANGELOG.md`, `docs/RULE_ENGINE_LIMITATIONS.md`. Không tối ưu theo nhãn khi xuất lại.
- Alert schema v1.0 đã đóng băng kỹ thuật; xác nhận của Tuấn còn `pending`. Dashboard chưa được nối tự động trong phạm vi bổ sung này.

Xem chi tiết field tại `ALERT_SCHEMA_V1.md`, `CORRELATION_API.md`, `EVENT_SCHEMA.md`.
