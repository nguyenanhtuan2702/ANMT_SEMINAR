# Đề xuất đồ án

## Ứng dụng AI trong phân tích nhật ký và phát hiện sự cố an ninh máy tính

## Tóm tắt

Đồ án xây dựng prototype phân tích nhật ký an ninh dạng CSV, kết hợp phát hiện
bất thường bằng Machine Learning với các luật được kiểm chứng trên dữ liệu.
Ứng dụng chuẩn hóa log, tạo đặc trưng hành vi theo thời gian, phát hiện sự
kiện đáng chú ý, liên kết các sự kiện thành timeline, gán mức ưu tiên xử lý
và hiển thị kết quả trên dashboard Streamlit.

Logistic Regression được dùng làm baseline và Random Forest làm mô hình
supervised chính; Random Forest được so sánh với các cấu hình feature khác.
Dashboard cho phép tải log, xem biểu đồ, lọc sự kiện và kiểm tra lý do cảnh báo. Kết quả
được xem là hỗ trợ analyst rà soát, không thay thế hệ thống SIEM hay xác nhận
cuối cùng về một sự cố.

## 1. Bối cảnh và vấn đề

Nhật ký máy tính đến từ nhiều hoạt động và nguồn khác nhau, có khối lượng lớn
và khó rà soát thủ công. Việc chỉ dựa vào một luật cố định có thể bỏ sót hành
vi chưa biết; ngược lại, mô hình ML có thể đưa ra điểm bất thường mà không
giải thích trực tiếp được ngữ cảnh. Analyst cần một quy trình kết hợp khả năng
sàng lọc của ML, các luật có lý do rõ ràng và timeline sự kiện liên quan.

Đồ án tập trung giải quyết câu hỏi:

> Làm thế nào xây dựng một prototype kết hợp Rule-based Detection và Machine
> Learning để sàng lọc log SPEDIA, liên kết các sự kiện liên quan, ưu tiên
> cảnh báo và hỗ trợ analyst điều tra trên dashboard?

## 2. Mục tiêu

- Khảo sát chất lượng, schema, phân bố nhãn và đặc điểm thời gian của dataset.
- Chuẩn hóa dữ liệu log nhưng giữ lại nội dung gốc để điều tra.
- Xây dựng pipeline ML không dùng nhãn làm feature, chia tập theo thời gian và
  có thể tái lập.
- Kết hợp Logistic Regression làm baseline và Random Forest làm mô hình chính.
- Xây dựng Rule Engine dựa trên tín hiệu xác thực trong dataset, trả lý do
  cụ thể cho mỗi cảnh báo.
- Correlate các sự kiện theo User/Agent và thời gian, chỉ dùng dữ liệu hiện
  tại/quá khứ.
- Gán severity có quy tắc và lý do, rồi trình bày sự kiện, cảnh báo, timeline
  và metric trên giao diện.

## 3. Phạm vi đồ án

### Trong phạm vi

- Nhận file CSV có schema phù hợp với dataset SPEDIA.
- Kiểm tra schema, chuyển kiểu thời gian, xử lý missing values và tạo khóa
  `source_row_id`.
- Phân tích dữ liệu bằng notebook EDA.
- Huấn luyện/đánh giá Logistic Regression và Random Forest, đồng thời so sánh
  các cấu hình feature của Random Forest.
- Chạy rule, correlation và severity theo cấu hình đã công bố.
- Hiển thị tổng quan, sự kiện, cảnh báo, chi tiết log gốc và kết quả đánh giá
  trên Streamlit.

### Ngoài phạm vi

- Thay thế SIEM hoặc hệ thống phản ứng sự cố production.
- Tự động cách ly máy, khóa tài khoản hoặc thực hiện hành động khắc phục.
- Khẳng định một sự kiện là tấn công chỉ dựa vào anomaly score.
- Đảm bảo chất lượng trên mọi định dạng log hoặc mọi tổ chức khác dataset.

## 4. Dataset và dữ liệu đầu vào

Dataset `logs_SPEDIA_annotated_en.csv` có 72.250 dòng và 24 cột, thời gian
từ 2025-03-06 đến 2025-03-30. Theo khảo sát, dữ liệu có 17 User, 83
Agent_name và các nhóm Activity gồm HTTP, email, file, command, session, device.
Nhãn `Anomaly` có 30.709 mẫu 0 (42,5%) và 41.541 mẫu 1 (57,5%).

| Nhóm trường | Cách sử dụng |
|---|---|
| `Timestamp` | Sắp xếp sự kiện, tạo giờ/ngày và cửa sổ thời gian |
| `User`, `Agent_name` | Nhóm hoạt động, correlation và tạo thống kê cửa sổ quá khứ |
| `Activity`, `Action`, `Decoder_name` | Feature phân loại và điều kiện luật đã xác minh |
| `Command`, `Url`, `Filename`, `Path` | Ngữ cảnh rule/điều tra theo loại sự kiện khi dữ liệu có trường |
| `Description`, `Full_log`, `Content` | Giữ lại để analyst xem; không dùng làm feature mặc định |
| `Level` | Không dùng làm feature mặc định do nguy cơ chứa tín hiệu nhãn |
| `id` | Định danh gốc nếu duy nhất; không dùng làm feature ML |
| `Anomaly` | Target huấn luyện/đánh giá; không bắt buộc ở inference và không làm feature |

Loader kiểm tra các trường bắt buộc. Normalizer chuyển `Timestamp` sang
datetime, chuẩn hóa missing values và giữ các trường gốc. Mỗi bản ghi có
`source_row_id` ổn định trong phạm vi file để nối kết quả giữa ML, rules,
correlation và dashboard.

## 5. Phương pháp Machine Learning

### 5.1 EDA và feature engineering

Notebook EDA khảo sát kiểu dữ liệu, missing values, dòng trùng, phân bố nhãn,
Activity, các trường phân loại và dữ liệu theo thời gian.

Feature ML ban đầu gồm:

- `hour`, `day_of_week`
- `Activity`, `Action`, `Decoder_name`
- `User`, `Agent_name` trong thực nghiệm feature đầy đủ
- `User_events_15min_past`, `Agent_name_events_15min_past`

Window feature đếm sự kiện của cùng User/Agent trong 15 phút trước bản ghi
hiện tại. Bản ghi hiện tại và các bản ghi sau nó không được tính. Trong
behavioral model, User/Agent không được đưa trực tiếp như categorical input,
nhưng danh tính vẫn gián tiếp ảnh hưởng đến phép nhóm sự kiện cửa sổ; đây là
một yếu tố cần lưu ý khi diễn giải.

### 5.2 Chia dữ liệu và pipeline

Dữ liệu được sắp theo Timestamp, chia tuần tự thành 64% train, 16% validation
và 20% test. Validation dùng chọn threshold; test là giai đoạn mới hơn để đánh
giá cuối. Encoder và scaler nằm trong sklearn Pipeline, fit trên train rồi áp
dụng nguyên trạng cho validation/test. Không dùng `Anomaly` làm đầu vào và
không dùng thống kê tương lai để tạo feature.

Threshold được chọn dựa trên mục tiêu phát hiện và validation tương ứng với
mô hình; giảm threshold thường tăng Recall và có thể tăng false positives,
còn tăng threshold có thể bỏ sót nhiều anomaly hơn. Anomaly score của model
không được mặc định xem là xác suất đã calibration.

### 5.3 Mô hình

1. **Logistic Regression:** baseline supervised.
2. **Random Forest:** mô hình supervised chính; so sánh cấu hình feature đầy
   đủ với cấu hình behavioral.

Pipeline hoàn chỉnh, gồm tiền xử lý và estimator, được lưu để inference dùng
cùng quy trình với huấn luyện.

## 6. Phát hiện theo luật, correlation và severity

### 6.1 Rule Engine

Rule Engine áp dụng các luật được kiểm chứng trên dataset; match là tín hiệu
cần rà soát, không phải kết luận tấn công:

- **Command:** `CMD_NMAP`, `CMD_JOHN`, `CMD_MSFCONSOLE` chỉ khớp khi Action là
  `command executed` và basename của Command trùng chính xác executable.
- **File:** `FILE_CONFIG_CHANGE` kiểm tra file modified/added/deleted trên
  nhóm path cấu hình đã định nghĩa. Với modified, chỉ bỏ qua khi raw xác nhận
  Changed attributes chỉ gồm mtime/ctime.
- **HTTP:** `HTTP_IP_HOST` khớp URL HTTP(S) có hostname là IP literal hợp lệ.
- **Authentication:** `AUTH_FAILURE_WINDOW` cần tín hiệu failure rõ trong
  Action/Description/Full_log và ít nhất 3 failure cùng User + Agent trong
  cửa sổ đóng 300 giây. Thiếu User thì không đếm.
- `CMD_NETCAT` không bật mặc định. Không có rule chỉ dựa vào tên Activity hay
  blacklist chưa kiểm chứng.

Mỗi alert có `timestamp`, `user`, `agent`, `activity`, `rule_id`, `reason`,
`severity`, `source_row_id` và các trường ngữ cảnh liên quan. Một sự kiện có
thể khớp nhiều luật; mỗi kết quả giữ rule_id và reason riêng để truy vết.

### 6.2 Event correlation

Correlation nhóm theo cặp User + Agent_name trong fixed window 900 giây căn
theo epoch; nhóm bị tách khi khoảng cách giữa hai event lớn hơn 300 giây.
Timestamp/record_index xác định thứ tự; thiếu User/Agent hoặc Timestamp lỗi
thì event không được gán group. Timeline có `source_row_id`; alert không có
group vẫn được giữ lại. Dùng prefix tới thời điểm alert để tính severity,
không dùng event tương lai cho quyết định.

### 6.3 Severity

Severity là mức ưu tiên xử lý của prototype, không phải kết luận về thiệt hại.
Mỗi mức có reason để người dùng hiểu căn cứ:

| Mức | Nguyên tắc gán mức ưu tiên |
|---|---|
| LOW | Một alert ML đơn lẻ hoặc rule có mức gốc LOW |
| MEDIUM | Một rule có bằng chứng; các rule command/file/auth hiện có mức gốc MEDIUM |
| HIGH | ML cùng khớp một event với rule, nhiều loại rule trên cùng event, hoặc prefix group có ít nhất 3 event rule-alert / ít nhất 2 loại rule |
| CRITICAL | Prefix group có ít nhất 10 event rule-alert, ít nhất 3 loại rule và có ML alert corroboration |

Mỗi alert lưu base severity và `severity_reason` gồm các tín hiệu/điều kiện
được dùng. ML score cao một mình không nâng mức; severity là mức ưu tiên rà
soát chứ không phải mức tác động đã xác minh.

## 7. Dashboard và luồng sử dụng

Dashboard Streamlit thực thi luồng qua orchestrator và tổ chức các màn hình sau:

- **Tổng quan:** tổng sự kiện, số cảnh báo ML/Rule, số nhóm tương quan, phân bố
  Activity, cảnh báo theo ngày và nguồn detector.
- **Sự kiện:** bảng sự kiện có lọc Activity, User, Agent và thời gian; giữ khả
  năng xem các trường log gốc.
- **Cảnh báo:** kết quả ML và Rule Engine, anomaly score/threshold, rule_id,
  reason và severity; có bộ lọc mức độ và nguồn phát hiện.
- **Điều tra:** chi tiết log gốc, các alert liên quan và timeline correlation
  theo User/Agent.
- **Đánh giá ML:** metric, confusion matrix, threshold và ghi chú drift/giới hạn.

Luồng xử lý:

`Upload CSV → validate schema → normalize → ML + Rule Engine → correlate
→ severity → filter/inspect trên dashboard`

Dashboard chỉ điều phối module và trình bày kết quả; không tự triển khai lại
logic ML, rule, correlation hoặc severity. Trạng thái detector chưa chạy được
phân biệt với trường hợp đã chạy nhưng không sinh alert. Event thiếu Timestamp
được giữ lại để kiểm tra nhưng bỏ qua cho ML/correlation.

## 8. Hợp đồng dữ liệu giữa các module

| Module | Đầu vào | Đầu ra |
|---|---|---|
| Loader/Normalizer | CSV và schema | DataFrame chuẩn hóa, Timestamp datetime, log gốc và `source_row_id` |
| ML Engine | DataFrame chuẩn hóa | `source_row_id`, `predicted_label`, `anomaly_score` |
| Rule Engine | Event chuẩn hóa | Danh sách alert có rule_id, reason, severity và `source_row_id` |
| Correlation | Event/alert có timestamp và actor | Nhóm/timeline có thứ tự và các `source_row_id` |
| Severity | Alert ML/Rule và prefix correlation | LOW/MEDIUM/HIGH/CRITICAL cùng base level và reason |
| Dashboard | Event, prediction, alert, group và metric | Tổng quan, cảnh báo, bộ lọc, chi tiết điều tra |

Anomaly không được yêu cầu ở inference. Khóa nối phải được kiểm tra tính duy
nhất trong file; không mặc định `id` duy nhất nếu chưa xác minh.

## 9. Kết quả thực nghiệm hiện có

Các kết quả ML dưới đây là trên temporal split đã mô tả; threshold được chọn
trên validation rồi áp dụng để tính metric trên test:

| Mô hình/thực nghiệm | Accuracy | Precision | Recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|---:|
| Logistic Regression, feature đầy đủ | 0.9998 | 1.0000 | 0.9998 | 0.9999 | 1.0000 |
| Random Forest, feature đầy đủ | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Random Forest behavioral | 0.9839 | 0.9921 | 0.9910 | 0.9915 | 0.9998 |

Threshold được chọn trên validation lần lượt khoảng 0.4125, 0.54 và 0.18.
Các con số gắn với đúng lần chạy/model/dataset này; không suy rộng sang mọi
log khác. Các bảng alert/severity tạo sẵn trong `data/processed/` là snapshot
offline theo policy của bundle; severity realtime trên dashboard dùng policy
ML-rule trong mục 6.3 nên phân phối severity có thể khác.

### 9.1 Drift và diễn giải

Tỷ lệ `Anomaly=1` trong train là khoảng 44,5%, validation 62,5% và test
95,0%. Train kết thúc lúc 2025-03-26 22:12:28; test bắt đầu lúc 2025-03-30
10:19:36. Đây là lệch phân bố nhãn đáng kể cần được nêu khi giải thích metric.

Phép kiểm tra ngẫu nhiên 5-fold với riêng User + Agent_name đạt F1=1.00.
Đây là cảnh báo về pattern Identity gắn với nhãn/dataset, không phải bằng
chứng mô hình tổng quát hóa hoàn hảo. Behavioral Random Forest giảm việc dùng
Identity trực tiếp nhưng các window count vẫn được nhóm theo User/Agent.
Vì vậy kết quả cao cần được trình bày cùng drift và giới hạn dữ liệu.

Các trường Level, Description, Full_log và Content được sàng lọc riêng và
không đưa vào feature chính. Kết quả sàng lọc đơn biến không đủ để kết luận
chắc chắn có hay không có leakage; quyết định loại các cột này được giữ lại
cho tới khi có đánh giá chặt chẽ hơn.

## 10. Kiểm thử và tiêu chí nghiệm thu

- Loader từ chối file rỗng, CSV lỗi hoặc thiếu trường bắt buộc bằng thông báo rõ.
- Normalizer tạo Timestamp hợp lệ, giữ log gốc và khóa source row ổn định.
- Kiểm thử window chứng minh không dùng bản ghi hiện tại/tương lai.
- ML inference chạy khi không có cột `Anomaly` và trả đúng schema đầu ra.
- Mỗi rule có test case kích hoạt, không kích hoạt và lý do tương ứng.
- Correlation trả timeline có thứ tự; không lấy sự kiện tương lai.
- Severity trả mức hợp lệ và reason truy vết được.
- Kiểm thử tích hợp xác nhận luồng upload → detect → correlate → severity
  → dashboard chạy trên CSV mẫu.
- Báo cáo giữ riêng metric ML và kết quả rule test; không trình bày rule như
  một mô hình ML hay gộp các metric không tương đương.

## 11. Rủi ro và kiểm soát

| Rủi ro | Kiểm soát |
|---|---|
| Leakage từ Anomaly/id/Level hoặc log text | Chặn Anomaly/id khỏi feature; loại cột nghi ngờ khỏi pipeline chính; kiểm tra ablation |
| Drift theo thời gian/actor | Temporal split, báo cáo drift và kiểm thử thêm trên giai đoạn/actor khác |
| Rule không phù hợp dataset | Chỉ bật rule có bằng chứng; lưu rule_id và reason; đánh giá bằng test cases |
| Correlation dùng thông tin tương lai | Dùng thứ tự Timestamp và window chỉ nhìn về quá khứ |
| False positive gây quá tải | Hiển thị score, threshold, reason; cho phép lọc và analyst xác minh |
| Severity gây hiểu nhầm | Ghi rõ đây là mức ưu tiên prototype, không phải mức độ tác động đã xác nhận |
| Lộ dữ liệu nhạy cảm | Giữ dataset/log trong môi trường nhóm; không commit raw logs hoặc file FP/FN có dữ liệu gốc |
| Model artifact không tương thích | Ghim phiên bản Python/thư viện và kiểm thử model sau khi tải/cài đặt |

## 12. Phân công thành viên

| Thành viên | Trách nhiệm |
|---|---|
| Ngọc | EDA, feature engineering, Logistic Regression, Random Forest, metric, drift, model artifact và ML inference |
| Thọ | CSV loader, normalizer, Rule Engine, event correlation, severity và test cho các module xử lý/phát hiện |
| Tuấn | Streamlit dashboard, upload, lọc, biểu đồ, tích hợp các module, README và kịch bản demo |

Phân công theo bảng Excel và `docs/PHAN_CONG.md`. Tài liệu hướng dẫn PDF có
chỗ ghi khác vai trò Tuấn/Thọ; phân công cuối cùng theo thống nhất của nhóm.

## 13. Sản phẩm bàn giao

- Mã nguồn Python có cấu trúc và ứng dụng Streamlit.
- CSV loader/normalizer và hợp đồng dữ liệu module.
- Rule Engine với rule_id, reason và test cases.
- Correlation timeline và severity mapping có giải thích.
- Notebook EDA, ML pipelines/model artifacts và hướng dẫn inference.
- Báo cáo metric, confusion matrix, threshold, drift và phân tích FP/FN.
- README cài đặt/chạy, báo cáo đồ án, slide và kịch bản demo.

## 14. Kết luận

Đồ án trình bày một prototype phát hiện bất thường theo hướng nhiều lớp:
chuẩn hóa log, supervised/unsupervised ML, rule-based detection, event
correlation, severity và dashboard. Giá trị của prototype không chỉ nằm ở
điểm metric mà còn ở khả năng truy vết từ cảnh báo về log gốc, giải thích lý
do, và công khai giới hạn do drift, dữ liệu mô phỏng và nguy cơ phụ thuộc
Identity.
