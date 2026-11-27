# Pipeline rule-based — Task 8

Nội dung tích hợp Task 8 được ghi dưới tiêu đề **Task 9** trong report_npt.md theo yêu cầu đặt tên báo cáo. Artifact kiểm chứng lưu tại reports/pipeline_integration.

## Hợp đồng gọi trực tiếp

```python
from detection.pipeline import run_detection_pipeline

result = run_detection_pipeline(df_normalized)
logs = result["detected_logs"]
table = result["alert_table"]
groups = result["groups"]
```

`run_detection_pipeline(df_normalized: pd.DataFrame, *, severity_config=None) -> PipelineResult` nhận DataFrame từ `normalize(load_logs(source))` hoặc `read_normalized_logs`. Có thể đổi cấu hình severity bằng path/dict đầy đủ theo Task 7; correlation dùng chung config đó. Mặc định rules.json đã đóng băng, chưa có nhánh ML.

| Key kết quả | Kiểu và ý nghĩa |
|---|---|
| status | `success`; trường hợp lỗi ném exception, không trả kết quả rỗng giả thành công |
| detected_logs | DataFrame đầu vào giữ thứ tự/index và mọi cột, cộng bốn cột detection |
| atomic_alerts | list atomic 11 field, đã chấm severity |
| alerts | list merged v1.0 12 field, đã chấm severity |
| alert_table | DataFrame merged cố định 12 cột, kể cả khi rỗng |
| groups | DataFrame correlate 12 cột; summary toàn snapshot để hiển thị |
| report | status, số dòng/alert/nhóm, policy, báo cáo rule/correlation và timings_seconds |

`PipelineError` kế thừa ValueError, có `.report` gồm status=error, stage và nguyên nhân. Thiếu cột/tên trùng, source ID trùng, sai datetime hay input đã có cột detection báo lỗi rõ. Schema tùy rule từ Rule Engine vẫn được kiểm tra, không âm thầm tắt rule thiếu dữ liệu. Kết quả zero alert sau thành công khác lỗi/chưa chạy; severity của event không có alert là null.

## Bốn cột gắn vào log

| Cột | Kiểu trong bộ nhớ | Ngữ nghĩa nhân quả |
|---|---|---|
| rule_ids | list[str] đã sort/duy nhất | Rule khớp chính event đó; không khớp là [] |
| alert_count | Int64 không thiếu | Số rule khớp chính event, bằng len(rule_ids); không phải số alert cuối nhóm |
| group_id | string nullable | Nhóm User/Agent/fixed-window/gap chứa event; thiếu ngữ cảnh là null |
| severity | string nullable | Mức ưu tiên đã điều chỉnh đến anchor; không có alert là null |

Tất cả join bằng source_row_id; không join bằng index hoặc id nguồn. Reset index chỉ trên bản làm việc nội bộ, đầu ra vẫn giữ index và thứ tự input. Full_log, Description, Content và khóa gốc giữ nguyên. Nếu có Anomaly/Level, chúng còn nguyên ở output để đánh giá nhưng bị bỏ khỏi đầu vào rule/correlation/severity.

Group ID được tạo với min_events=1 để sự tồn tại nhóm không chờ đủ event tương lai; pipeline từ chối min_events khác 1. Severity tích lũy duy nhất đến Timestamp/record_index của từng alert. Không gắn end_time, event_count/alert_count cuối nhóm hay danh sách hoạt động tương lai vào detected logs. Min_events chỉ là bộ lọc hiển thị ở caller nếu cần.

Ngọc có thể chọn rule_ids/alert_count/severity làm đặc trưng rule-based, nhưng phải giữ policy cố định, chỉ dùng lịch sử tới cutoff, chia train/test theo thời gian và fit bộ mã hóa trên train. Anomaly là nhãn, không phải feature. group_id/source_row_id là khóa để join/nhóm, không nên đưa nguyên chuỗi định danh vào mô hình; namespace dựa trên hash nguồn là quy ước nhận diện. Cam kết prefix giữ nguyên cần cùng source IDs và policy; upload file đã thay byte tạo namespace mới, late arrival không thuộc cam kết append-only.

## Upload và dashboard

`dashboard.service.run_upload_pipeline(source)` nhận path hoặc upload nhị phân, gọi loader → normalize → pipeline, thêm thời gian load/normalize/upload_total vào report. Streamlit dùng chính hàm này; cache theo byte upload và hash rules/policy để rerun bộ lọc không chạy lại detection. Tối đa hai cache entry trong bộ nhớ.

Dashboard có trạng thái chưa upload/lỗi/thành công/zero alert; hiển thị event chuẩn hóa, alert ưu tiên, evidence/reason raw và timeline. Bộ lọc Activity/User/Agent chỉ lọc hiển thị; không chạy detection trên trang đã lọc nên không mất lịch sử. Tab ML ghi chưa chạy. Timeline là snapshot file upload; không dùng summary đó như thông tin quá khứ của event.

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Chọn CSV gốc, không upload detected/normalized CSV qua raw loader. File normalized/detected đã có source IDs phải đọc bằng reader tương ứng để giữ namespace và kiểu dữ liệu.

## Export và kiểm chứng

```powershell
.\.venv\Scripts\python.exe -W ignore::DeprecationWarning -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -W ignore::DeprecationWarning -m detection.export_detected_dataset --check-dashboard
```

Lệnh export chạy file gốc qua cùng service với widget upload, xuất `data/detected_logs.csv` + `.schema.json`, kiểm tra round-trip lossless, raw/khóa theo CSV gốc, bỏ nhãn/Level và ba cutoff. `--check-dashboard` dùng Streamlit AppTest trên widget upload thật, bảng overview/alert/timeline và filter rerun; không phải xác nhận trực tiếp của Tuấn hoặc kiểm thử trình duyệt thủ công.

```python
from preprocessing.detected_io import read_detected_logs, save_detected_logs
detected = read_detected_logs("data/detected_logs.csv")
```

Reader khôi phục JSON rule_ids thành list, datetime, nullable integer/boolean, null/empty và nguyên raw từ CSV/sidecar. CSV được ignore Git; chuyển cùng sidecar khi bàn giao. Metadata sử dụng transport normalized v1 với attrs detection_schema_version=spedia.detected.v1; không đọc bằng raw loader hoặc pd.read_csv mặc định cho inference.

reports/pipeline_integration/pipeline_validation.json và timings.csv ghi số lượng, phiên bản thực chạy, thời gian từng bước, kiểm tra bất biến và trạng thái AppTest. Bảng thời gian đo trên máy hiện tại, một lần chạy có cả bước kiểm chứng; không cộng pipeline_total với các bước con và không coi kết quả là benchmark mọi máy. Pipeline tái sử dụng nhóm chuẩn vừa tạo khi tính severity, tránh tái nhóm toàn dataset; assign_severity công khai vẫn tự xác minh membership của caller. Test kiểm tra hai đường cho cùng kết quả. Dashboard cache riêng pipeline và timeline để tránh tính lại khi chỉ lọc.

Tuấn chưa trực tiếp chạy nghiệm thu cùng agent; tài liệu/API và kiểm thử tự động đã sẵn sàng để review. ML, late-arrival/streaming state và lịch vận hành/timezone được xác minh vẫn ngoài phạm vi.

Kết quả môi trường .venv: 159 test đạt trên Python 3.12.14/pandas 2.3.3/Streamlit 1.67.0. Full dataset 72.250 event × 47 cột, 1.301 alert event/7.501 nhóm. Sau tối ưu: pipeline 5,336s; upload/normalize/pipeline 8,402s; AppTest khởi tạo/upload/render 12,692s; filter rerun cache 0,868s. CSV trước/sau tối ưu có cùng SHA-256; xem reports/pipeline_integration/optimization_checks.json. Thay code khi phát triển cần restart hoặc clear cache; hash rule/policy tự đổi key khi cấu hình thay đổi.
