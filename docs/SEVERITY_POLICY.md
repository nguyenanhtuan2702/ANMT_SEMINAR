# Severity policy v1 — ưu tiên xử lý prototype

Severity không phải mức tác động đã xác minh. Không dùng `Anomaly`, `Level`, điểm ML hoặc tên Activity để kết luận tấn công. Các ngưỡng bên dưới là lựa chọn minh bạch của prototype, chưa được hiệu chỉnh theo tổ chức hoặc tối ưu bằng nhãn.

Thỏa thuận tích hợp ML giữ nguyên policy này: model chỉ cung cấp prediction/score riêng; không truyền score vào `assign_severity()` và không sửa schema alert. Xem [hợp đồng tích hợp ML](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md).

## Mapping và cách tính

Nguồn duy nhất cho mức gốc là `base_severity` trong `detection/rules.json`. Không lấy mức incoming làm gốc để tránh cộng dồn khi gọi lại.

| Rule | Mức gốc | Lý do ưu tiên |
|---|---|---|
| CMD_NMAP | MEDIUM | Xem xét công cụ khảo sát mạng; có thể là log kết thúc tiến trình |
| CMD_JOHN | MEDIUM | Xem xét công cụ kiểm thử mật khẩu và ủy quyền |
| CMD_MSFCONSOLE | MEDIUM | Xem xét console kiểm thử khai thác và tham số |
| FILE_CONFIG_CHANGE | MEDIUM | Kiểm tra thay đổi cấu hình và quản trị hợp lệ |
| AUTH_FAILURE_WINDOW | MEDIUM | Kiểm tra cụm failure rõ ràng, chưa xác nhận brute force |
| HTTP_IP_HOST | LOW | Truy cập IP trực tiếp chỉ là ngữ cảnh |
| CMD_NETCAT | LOW | Tool kết nối có nhiều mục đích hợp lệ; rule vẫn mặc định tắt |

Policy bổ sung ở `detection/severity_policy.json`, đọc qua `load_severity_config(config=None)`; config nhận đường dẫn hoặc dictionary đầy đủ, trả dictionary độc lập đã kiểm tra.

| Yếu tố tại alert hiện tại | Điều chỉnh |
|---|---|
| Dưới 3 event có alert trong prefix nhóm | +0 |
| Từ 3 đến 9 event có alert | +1 bậc |
| Từ 10 event có alert | +2 bậc, thay cho +1 ở ngưỡng 3 |
| Ít nhất 3 loại hoạt động khác nhau trong prefix nhóm | +1 bậc |
| Giờ nguồn ngoài `[08:00,18:00)` | +1 bậc |
| Trong giờ làm việc hoặc thiếu nhóm | Yếu tố đó +0, không tự giảm |

Thứ tự `LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3`. Tổng điều chỉnh bị giới hạn **2 bậc**, sau đó chặn kết quả tại CRITICAL. Không có chính sách giảm mức tự động vì chưa có bằng chứng để cho rằng giờ làm việc hoặc thiếu dữ liệu làm giảm nhu cầu xử lý. `severity_reason` ghi rule/mức gốc, số event alert, số loại hoạt động, giờ nguồn, bước tăng từng yếu tố và các trần. `reason` gốc của detector được giữ nguyên.

Khung giờ dùng đồng hồ naive của nguồn; dataset chưa xác minh timezone, lịch trực hay cuối tuần. Không tự chuyển sang giờ Việt Nam. Có thể tắt yếu tố giờ bằng off_hours_steps=0 hoặc đổi giờ trong config khi nhóm xác minh lịch vận hành. Activity chỉ đếm độ đa dạng, không phân loại tên nào là tấn công.

## API và luồng sử dụng

```python
from preprocessing.normalized_io import read_normalized_logs
from detection.shared_output_io import read_atomic_alerts, read_event_groups
from detection.severity import assign_severity
from detection.alert_aggregation import merge_alerts

events = read_normalized_logs("data/normalized_logs.csv")
atomic = read_atomic_alerts()
groups = read_event_groups()
prioritized_atomic = assign_severity(atomic, groups, events=events)
prioritized_events = merge_alerts(prioritized_atomic)
```

`assign_severity(alerts: list[Alert], correlations=None, ml_results=None, *, events=None, config=None) -> list[Alert]` trả bản sao atomic 11 field, thay severity/severity_reason. Tham số `ml_results` được giữ tương thích nhưng luôn bỏ qua trong policy v1. Task 11 tích hợp ML ở Dashboard riêng; không truyền score vào hàm này và không đổi policy v1.

`correlations` nhận DataFrame `correlate()` hoặc list từ adapter `correlate_events()`. Nếu có correlations, bắt buộc có events chuẩn hóa. Nếu có events và correlations=None, module tự nhóm theo policy; correlations=[] nghĩa là không có nhóm được cung cấp. Nếu không có cả events lẫn correlations, chỉ tính mức gốc và yếu tố giờ, ghi rõ thiếu ngữ cảnh. Không tự suy nhóm từ user/agent trên alert.

Đầu vào phải là alert atomic hợp lệ, dùng rule_id có mapping trong rules.json. Với merged v1.0 hãy lấy lại atomic Task 4, chấm rồi merge; không sửa riêng severity root vì sẽ phá invariant max severity của các rule_matches. Kết quả merged Task 7 giữ schema v1.0; mức gốc không còn là mức cuối trong từng match, nhưng vẫn tra được trong rules.json và severity_reason. Reason giải thích điều chỉnh nằm trong từng match, root là mức cao nhất. Không ghi đè bản đóng băng Task 5.

## Ngữ cảnh nhân quả

Module tính lại membership bằng correlation với fixed window 900s/gap 300s/min_events=1 (cấu hình được). Kiểm tra group_id/source_row_ids cung cấp phải khớp events/config/snapshot; không tin summary count/activity cuối nhóm.

Sau sort Timestamp/record_index, dùng groupby.cumsum cho unique event có alert và hoạt động xuất hiện lần đầu. Đếm event có alert, không đếm rule matches hay bản gửi lặp; bao gồm event hiện tại. Hoạt động không có alert vẫn cung cấp ngữ cảnh đa dạng. Các event khác User/Agent, khác bucket hoặc cách quá gap không cộng chung.

Nguồn thiếu User không được gán nhóm giả; alert vẫn được chấm base + giờ. Chỉ số contextual phụ thuộc tập alert đã cung cấp: hãy truyền đầy đủ lịch sử alert trong snapshot, không chỉ các dòng đang hiển thị trên trang dashboard. Chạy inference tại cutoff phải lọc events và alerts tới cùng `(Timestamp, record_index)` rồi tạo groups cùng snapshot. Severity của prefix cũ không đổi khi nối thêm sự kiện tương lai; late arrival và đổi source/config vẫn ngoài cam kết.

## Kiểm chứng

```powershell
python -m unittest discover -s tests -p test_severity.py -v
python tests/validate_severity_dataset.py
```

Có 20 test severity, tổng project 141 test. Audit thực tế trên 72.250 event/1.301 alert: LOW 48, MEDIUM 635, HIGH 446, CRITICAL 172; 675 alert đổi mức so với base. Tính severity gồm tái nhóm khoảng 1,676 giây trong lần audit, không bao gồm đọc/ghi file. Các con số là phân phối ưu tiên, không phải số tấn công hoặc tác động thật.

`reports/severity_assignment/severity_validation.json` ghi cấu hình/hash, ba cutoff kiểm tra nhân quả, nhãn/ML độc lập, idempotence, raw bất biến và CSV round-trip. `examples.json` có ví dụ thật đủ bốn mức. Kết quả kiểm chứng xuất riêng `prioritized_atomic_alerts.csv` và `prioritized_alerts_v1.0.csv`, mỗi file kèm `.schema.json`; Dashboard không đọc trực tiếp hai artifact CSV này mà tính severity qua upload pipeline Task 8. Tuấn đã xác nhận policy grouping/severity trong nghiệm thu Giai đoạn 1 ngày 27/11/2026.
