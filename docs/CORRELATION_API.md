# Event Correlation — API Task 6

Ngày triển khai: 22/11/2026. Không thay đổi rule/config/alert schema v1.0 đã đóng băng ở Task 5. Tuấn xác nhận quy tắc grouping/correlation trong nghiệm thu Giai đoạn 1 ngày 27/11/2026; Dashboard dùng pipeline Task 8 để hiển thị nhóm và timeline. Kế hoạch ML tại [tài liệu thống nhất kỹ thuật](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md) không thay đổi correlation và không dùng summary tương lai làm feature.

## Cách gọi

```python
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize_logs
from detection.rule_engine import detect_rules
from detection.alert_aggregation import merge_alerts
from detection.correlation import correlate, get_timeline

events = normalize_logs(load_logs("dataset_log/logs_SPEDIA_annotated_en.csv"))
alerts = merge_alerts(detect_rules(events))
config = {"window_seconds": 900, "max_gap_seconds": 300, "min_events": 1}
report = {}
groups = correlate(events, alerts, config=config, report=report)

group_id = groups.iloc[0]["group_id"]
timeline = get_timeline(events, group_id, alerts, config=config)

# Snapshot lịch sử đến đúng một event, kể cả có nhiều event cùng timestamp:
anchor = timeline.iloc[-1]
as_of = (anchor["Timestamp"], int(anchor["record_index"]))
past_groups = correlate(events, alerts, config=config, as_of=as_of)
past_timeline = get_timeline(events, group_id, alerts, config=config, as_of=as_of)
```

Không chạy detector thì truyền alerts=None; đã chạy không có alert thì truyền []. Atomic list, merged list và DataFrame đều được nhận. Merged rule_ids phải là list, không phải JSON string chưa decode khi đọc CSV. Hàm kiểm tra tham chiếu về nguồn và shared context nếu được cung cấp; không thay thế toàn bộ wire validator atomic/merged Task 5.

## Định nghĩa nhóm

Mỗi event có User/Agent/Datetime hợp lệ được xét trong khóa `(User, Agent_name, bucket thời gian cố định)`. Bucket trái đóng/phải mở, căn theo epoch của nguồn naive; không tự gán UTC hoặc giờ Việt Nam. Sort Timestamp/record_index, tách nhóm khi diff > max_gap_seconds, rồi cumsum theo khóa để định vị segment.

Nhóm mặc định tối đa nằm trong một cửa sổ 15 phút, tách khi im lặng quá 5 phút. Hai event ở 12:14:59.999 và 12:15:00.000 bị tách dù chỉ cách 1ms vì khác bucket; hai event cùng bucket cách đúng 300 giây chưa bị tách vì gap. Cấu hình là prototype, không được tối ưu theo Anomaly.

Không gọi groupby.apply theo hàng/iterrows để quyết định membership. Các phép chính là groupby/diff/cumsum/transform, group aggregation và merge alert edges; việc đóng gói list/dict theo nhóm phục vụ đầu ra không phải thuật toán duyệt từng event để tách phiên.

Group ID dùng cấu hình + source_row_id đầu, không dùng số thứ tự nhóm toàn bảng. min_events chỉ ẩn nhóm quá nhỏ khỏi kết quả, không đổi ID của nhóm tồn tại và không khẳng định nhóm lớn đáng ngờ hơn.

## Nhân quả và tính bất biến

- Append event có tuple `(Timestamp, record_index)` lớn hơn prefix không đổi group_id của các event trước.
- Group live có thể nhận thêm event: event_count/end_time/activities/alert_count khi xem hiện tại sẽ tăng. Đóng băng toàn bộ summary live mà vẫn thêm event vào cùng nhóm là hai yêu cầu mâu thuẫn; API không giả vờ làm cả hai.
- Dùng **cùng as_of tuple** để xem snapshot cũ: cả group data và timeline không đổi khi tương lai được thêm vào. Run report có thể có rows_input khác vì batch được truyền vào lớn hơn; dữ liệu nhóm ở cutoff vẫn giữ nguyên.
- Giả định source_row_id và record_index cũ được giữ. Loader Task 2 hash toàn bộ byte file: mở lại CSV đã nối thêm byte là file namespace khác, không được coi là append cùng event IDs. Stream/late arrivals hoặc thay config cần quản lý phiên bản/state ở tầng điều phối, ngoài phạm vi Task 6.
- Correlation trong Task 6 không phải suy luận chuỗi tấn công, không dùng thông tin tương lai, không suy danh tính từ User thiếu, không nối nhiều agent thành một phiên.

## Schema nhóm và timeline

Groups có 12 cột: group_id, key, user, agent, start_time, end_time, event_count, activities, alert_count, rule_match_count, rule_ids, source_row_ids. key là dict user/agent; thời gian là pandas datetime naive, khi export JSON là ISO string. EventGroup TypedDict mô tả dạng serialize. Activities giữ thứ tự xuất hiện đầu tiên, rule_ids sort duy nhất, source_row_ids đúng thứ tự Timestamp/record_index.

alert_count đếm event có cảnh báo, không đếm số rule; rule_match_count đếm cặp event/rule duy nhất. None alerts tạo missing count vì chưa biết, không fill thành zero. Report.detector_state phân biệt not_run/success.

Timeline giữ các cột nguồn, raw và numeric flags, chỉ bỏ Anomaly. Thêm group_id, has_alert, alert_count (0/1), rule_match_count, rule_ids, alerts_evaluated. Nếu chưa chạy detector, has_alert/các count thiếu và alerts_evaluated=False. Không sửa Full_log, Description, Content; không lấy Level làm severity.

Sự kiện thiếu user/time/agent không đủ điều kiện vào nhóm và được báo số đếm; vẫn còn nguyên trong event DataFrame và alert gốc. Khi không có nhóm phù hợp hoặc bị min_events ẩn, get_timeline báo ValueError rõ ràng. Unknown source_row_id trong alert hoặc context khác event cũng báo lỗi thay vì nối sai dữ liệu.

## Demo và xác minh

`reports/event_correlation/examples.json` có 3 nhóm thật: auth cluster, cấu hình trong phiên làm việc, tool john và ngữ cảnh. Mỗi nhóm có cutoff để mở lại đúng snapshot và một CSV timeline. `groups.json/csv` chứa toàn bộ nhóm, `correlation_validation.json` chứa thời gian/kiểm chứng với thuật toán tuần tự độc lập.

```powershell
python -m unittest discover -s tests -p test_correlation.py -v
python tests/validate_correlation_dataset.py --input dataset_log/logs_SPEDIA_annotated_en.csv
```

correlate_events là adapter cho tên khung Task 1, trả một Correlation snapshot/nhóm, anchor là event cuối nhìn thấy; không phải sliding window cho từng event. Tích hợp mới dùng correlate/get_timeline.

## Bảng nhóm dùng chung

`data/event_groups.csv` cùng `data/event_groups.schema.json` là snapshot đầy đủ 7.501 nhóm. Đọc bằng `detection.shared_output_io.read_event_groups()` để lấy DataFrame đúng datetime/Int64/list/dict; alert cho get_timeline lấy bằng `read_alerts()`. Tạo lại bằng `python -m detection.export_shared_outputs`; xem [SHARED_OUTPUTS.md](SHARED_OUTPUTS.md). Có 1.131 alert event thuộc nhóm và 170 alert event thiếu User vẫn giữ trong alerts.csv. Không dùng summary toàn dataset làm thông tin quá khứ tại một event; dùng as_of tuple khi cần snapshot nhân quả.
