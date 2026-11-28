# Schema log chuẩn hóa dùng chung — Task 3 bổ sung

Ngày bổ sung: 22/11/2026. Schema logic: **spedia.events.v1**. Dataset hiện có **72.250 record, 43 cột**; mẫu dashboard **1.000 record** có cùng cột/kiểu. Inference không bắt buộc Anomaly, nên nguồn không nhãn có thể có 42 cột thay vì 43. Các cột nguồn bổ sung chưa biết vẫn được giữ.

Hợp đồng ML ngày 27/11/2026 cần `Decoder_name`; Normalizer bảo đảm cột này có mặt dưới dạng nullable string dù raw CSV không có. Vì vậy đây là điều kiện của event chuẩn hóa cho ML, không phải cột bắt buộc của raw Loader. Chi tiết tại [tài liệu thống nhất kỹ thuật](../THONG_NHAT_KY_THUAT_TICH_HOP_ML_DASHBOARD.md).

## File bàn giao và cách đọc

| File | Mục đích |
|---|---|
| `data/normalized_logs.csv` | Toàn bộ dataset đã chuẩn hóa cho Rule Engine, Correlation, dashboard và ML |
| `data/normalized_logs.schema.json` | Kiểu cột, null marker, số dòng, checksum và attrs của bản đầy đủ |
| `data/normalized_logs_sample.csv` | 1.000 record để Tuấn dựng bảng/bộ lọc dashboard |
| `data/normalized_logs_sample.schema.json` | Metadata của bản mẫu |

Chuyển **cả CSV và sidecar cùng tên** cho người dùng tiếp theo. Tệp CSV UTF-8/BOM có quoting/newline chuẩn; raw field có thể chứa xuống dòng nên số dòng vật lý không bằng số record. CSV không tự chứa dtype/attrs: helper dưới đây khôi phục datetime, date, nullable numeric, boolean, missing và metadata.

```python
from preprocessing.normalized_io import read_normalized_logs

events = read_normalized_logs("data/normalized_logs.csv")
dashboard_sample = read_normalized_logs("data/normalized_logs_sample.csv")
```

Không đưa CSV đã chuẩn hóa qua load_logs(): đó là loader cho log gốc và sẽ từ chối các cột metadata dành riêng. Đặc biệt không tái tạo source_row_id từ hash file xuất: khóa phải giữ namespace SHA-256 của CSV nguồn gốc. Checksum trong sidecar chỉ kiểm tra vận chuyển, không thay namespace khóa.

Không dùng pd.read_csv mặc định cho pipeline vì nó có thể chuyển chuỗi rỗng/NA thành missing, để Timestamp là string và làm mất attrs. Format dùng null marker được chọn không trùng giá trị string thực; chuỗi rỗng, `NA`, `null` hay raw whitespace thật vẫn được giữ riêng với pd.NA. Khi CSV/metadata thiếu hoặc bị sửa không khớp hash, helper báo lỗi.

Datetime trong CSV xuất có phần microsecond 6 chữ số; Timestamp nguồn chỉ có độ chính xác millisecond nên không mất thông tin. Helper khôi phục datetime64[ns]; Timestamp_raw vẫn giữ định dạng nguồn 3 chữ số ban đầu.

## Nguồn gốc các cột

**24 cột nguồn + 8 cột loader + 11 cột normalizer = 43 cột.** Normalizer đổi cách biểu diễn 6 trường nguồn, giữ 18 trường còn lại như đầu ra loader. Các số vốn đã được loader ép kiểu vẫn giữ giá trị sau normalizer; bản lexical gốc nằm ở cột số `_raw`.

### 18 cột nguồn giữ nguyên sau loader

| Cột | Kiểu sau đọc helper | Quy tắc |
|---|---|---|
| id | string | Giữ UUID nguồn; không dùng làm khóa nội bộ hoặc feature định danh tùy tiện |
| Description | string | Raw nguyên vẹn, kể cả chuỗi rỗng/whitespace/NA-like text |
| Full_log | string | Raw nguyên vẹn, kể cả nháy, dấu phẩy, CRLF/LF |
| Content | string | Raw nguyên vẹn; không coi từ khóa trong nội dung là auth failure |
| Url | string | Giữ URL nguồn, không lowercase/percent-decode ghi đè |
| To | string | Giữ danh sách người nhận và separator nguồn |
| Cc | string | Giữ nguồn |
| Bcc | string | Giữ nguồn |
| From | string | Giữ nguồn, không mặc định bằng User hệ thống |
| Attachments | Float64 nullable | Giá trị loader; thiếu vẫn thiếu, không điền 0 |
| Size | Float64 nullable | Giá trị loader |
| Size_before | Float64 nullable | Số âm được giữ và có cờ chất lượng |
| Size_after | Float64 nullable | Giá trị loader |
| Filename | string | Giữ tên và hoa/thường nguồn |
| Path | string | Giữ đường dẫn/hoa thường, không tự coi mọi /etc là tấn công |
| Command | string | Giữ tên/hoa thường executable, không casefold ở normalizer |
| Level | Float64 nullable | Mức nguồn, không phải severity prototype |
| Anomaly | string, tùy chọn | Nhãn tham chiếu; chỉ dùng target/evaluation, tuyệt đối không đưa vào feature/rule/severity |

### 6 cột nguồn được chuẩn hóa có bản sao trước biến đổi

| Cột | Kiểu | Xử lý |
|---|---|---|
| Timestamp | datetime64[ns] naive | Parse YYYY-MM-DD HH:MM:SS.mmm; lỗi thành NaT và có flag/reason |
| Activity | string nullable | Strip + casefold, rỗng thành pd.NA |
| Action | string nullable | Strip + casefold; không dịch URL accedida hoặc suy nghĩa tấn công |
| Decoder_name | string nullable | Strip + casefold; thiếu cột thêm nullable string |
| User | string nullable | Strip + casefold; không gộp alias root/root(uid=0) |
| Agent_name | string nullable | Strip + casefold; không suy Anomaly từ hậu tố simulation |

### 8 cột do loader thêm

| Cột | Kiểu | Ý nghĩa |
|---|---|---|
| source_row_id | string | SHA-256 byte file gốc + record_index đệm ít nhất 8 số; giữ nguyên sau sort/sample/export/read |
| record_index | int64 | Index record CSV gốc bắt đầu 0, không phải dòng vật lý; sample có khoảng trống là bình thường |
| Attachments_raw | string | Lexical field nguồn trước ép số |
| Size_raw | string | Lexical field nguồn trước ép số |
| Size_before_raw | string | Lexical field nguồn trước ép số |
| Size_after_raw | string | Lexical field nguồn trước ép số |
| Level_raw | string | Lexical field nguồn trước ép số |
| has_numeric_issue | bool | Có số âm hoặc invalid/nonfinite; không phải flag tấn công |

### 11 cột do normalizer thêm

| Cột | Kiểu | Ý nghĩa |
|---|---|---|
| Timestamp_raw | string | Timestamp đầu vào normalizer, giữ đúng chuỗi nguồn |
| Activity_raw | string | Activity trước strip/casefold |
| Action_raw | string | Action trước strip/casefold |
| Decoder_name_raw | string | Decoder trước strip/casefold |
| User_raw | string nullable | User từ loader trước normalizer; loader đã chuyển User thiếu thành pd.NA, không phải bản sao byte field rỗng |
| Agent_name_raw | string | Agent trước strip/casefold |
| hour | Int64 nullable | 0–23; thiếu khi time lỗi |
| day_of_week | Int64 nullable | Monday=0, Sunday=6; thiếu khi time lỗi |
| date | datetime.date, dtype object | Ngày lịch; NaT khi Timestamp lỗi |
| invalid_timestamp | bool | Có time thiếu/sai/ngoài miền; giữ event |
| timestamp_error | string nullable | missing_timestamp / invalid_format / invalid_datetime / pd.NA |

Thứ tự cột lõi do EVENT_COLUMNS trong log_normalizer quy định; thứ tự toàn bộ 43 cột và dtype máy đọc được liệt kê đúng trong normalized_logs.schema.json. Srcip không có trong nguồn hiện tại, không tự bịa hoặc thêm IP suy diễn.

## Một hàm cho train và inference

```python
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize, normalize_logs

assert normalize is normalize_logs
train_events = normalize(load_logs("data/raw/logs_SPEDIA_annotated_en.csv"))
new_events = normalize(load_logs("new_unlabeled_logs.csv"))
```

normalize là cùng function object với normalize_logs, không phải bản sao cách làm sạch. Không fit tham số từ nhãn hoặc từ toàn dataset. Hàm nhận DataFrame đã có nguồn/khóa từ loader; nếu tự tạo raw DataFrame thiếu source_row_id, caller phải truyền file_sha256 đúng byte file gốc. Hàm không đoán hash để đổi khóa theo từng tập train/test.

Đây là chuẩn hóa log chung, chưa phải feature matrix ML. Ngọc phải tách Anomaly làm target (nếu có), loại khỏi features và fit encoder/scaler/vectorizer trên train theo pipeline ML. Agent_name có thể tiết lộ nguồn sinh simulation; không mặc định coi mọi cột dữ liệu chung là feature an toàn. Các raw field vẫn giữ để điều tra.

## Mẫu dashboard

Sample lấy một event đầu tiên mỗi Activity rồi lấy ngẫu nhiên phần còn lại không hoàn lại, seed 20261122, sort lại theo thời gian. Có đúng 1.000 source_row_id gốc, phủ cả 6 Activity; không chọn theo Anomaly. Thống kê: http 325, email 253, file 169, command 124, session 66, device 63.

Mẫu phục vụ dựng giao diện/bộ lọc, không đại diện đầy đủ lịch sử. Không dùng nó để tính recall toàn dataset hoặc kiểm chứng cửa sổ correlation vì đã bỏ nhiều event trung gian. Ghi chú Task 3 về việc nối dashboard đã được thay thế bởi tích hợp Task 8: Dashboard hiện nhận CSV gốc qua loader → normalizer → pipeline; `read_normalized_logs` dành cho caller đọc artifact chuẩn hóa.

## Tạo lại và kiểm tra

```powershell
python -m preprocessing.export_normalized_dataset --input data/raw/logs_SPEDIA_annotated_en.csv
python tests/validate_normalized_dataset.py
python -m unittest discover -s tests -p test_normalized_io.py -v
```

CSV + sidecar có thể đọc bằng dependencies hiện tại, không cần engine Parquet mới. Chúng là artifact dữ liệu cục bộ, được ignore Git theo chính sách data/; code, tài liệu và báo cáo validation vẫn trong repo. Không sửa CSV bằng Excel rồi ghép lại sidecar cũ: checksum sẽ từ chối dữ liệu không còn đúng bản xuất.
