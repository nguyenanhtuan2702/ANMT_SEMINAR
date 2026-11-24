# Hợp đồng module — Task 1 đến Task 8

Trạng thái ngày 22/11/2026: **giao diện kỹ thuật để nhóm xác nhận**, chưa có nghiệm thu trực tiếp của Tuấn. Loader, normalizer, Rule Engine, gộp/đánh giá alert, correlation/timeline và severity theo ngữ cảnh đã nối vào dashboard qua pipeline Task 8. ML chưa tham gia. Nội dung Pipeline được ghi dưới mục Task 9 trong report_npt.md theo yêu cầu tên báo cáo.

Task 5 bổ sung gộp alert, đánh giá tham chiếu và **đóng băng kỹ thuật alert schema v1.0**. Giao diện chi tiết ở `docs/ALERT_SCHEMA_V1.md`, JSON Schema/hash ở `docs/schemas/`; xác nhận của Tuấn vẫn pending. Không tuyên bố nhóm đã phê duyệt.

Task 6 triển khai correlation/timeline; Task 7 triển khai ưu tiên severity theo rule và prefix ngữ cảnh. Alert schema v1.0 và rules Task 5 giữ nguyên. Backend inference ML hiện có trong repo nhưng chưa được gọi trong pipeline/dashboard rule-based; ghép ML vào severity còn chờ Task 11. API grouping được chốt kỹ thuật theo yêu cầu mới bên dưới, thay đề xuất sliding-window chưa triển khai ở Task 1.

## Schema đầu vào

- CSV UTF-8 (chấp nhận BOM), dấu phẩy, quoting CSV chuẩn, có thể chứa newline trong field.
- Cột bắt buộc: `id`, `Timestamp`, `Agent_name`, `User`, `Activity`, `Action`. Dashboard cũ chỉ yêu cầu 5 cột (không có `id`); đây là hợp đồng pipeline mới cần nhóm xác nhận.
- `id`, `Timestamp`, `Agent_name`, `Activity`, `Action` không được rỗng sau kiểm tra whitespace. `User` bắt buộc có cột nhưng giá trị có thể thiếu. Không tự loại dòng thiếu User.
- Kiểm tra trùng `id`, báo cáo và giữ các dòng; không tự xóa trùng. Khóa nội bộ là `source_row_id`.
- Các cột khác tùy chọn, gồm `Decoder_name`, `Full_log`, `Description`, `Content`, `Url`, `To`, `Cc`, `Bcc`, `From`, `Attachments`, `Size`, `Size_before`, `Size_after`, `Filename`, `Path`, `Command`, `Level`, `Srcip`, `Anomaly`. Giữ cột bổ sung chưa biết. CSV khảo sát không có `Srcip`.
- `Anomaly` chỉ dùng đánh giá sau cùng. Rules, correlation và severity không được đọc/đưa nhãn này vào evidence hay logic. Inference không yêu cầu nhãn; không dùng nhãn làm feature ML.
- Giữ nguyên giá trị raw `Full_log`, `Description`, `Content` sau giải mã CSV. Không strip/lowercase/fillna ghi đè; việc tìm kiếm dùng bản tạm. Chuỗi `NA` không tự chuyển thành null. Field raw thiếu vẫn biểu diễn thiếu.

## Khóa và chuẩn hóa

`source_row_id = "<sha256 toàn bộ byte file gốc>:<record_index:08d>"`.

- SHA-256 là 64 ký tự hex thường; `record_index` integer bắt đầu 0 sau header, đếm **bản ghi CSV**, không đếm dòng vật lý. Loader thêm cả `record_index` và `source_row_id` trước sort/filter.
- Cùng byte file và vị trí bản ghi cho cùng khóa, kể cả khi `id` trùng. Đổi file làm đổi namespace khóa. Không dùng tên/đường dẫn file làm file_id. Giữ khóa qua mọi module.
- Timestamp nguồn là `YYYY-MM-DD HH:MM:SS.mmm`; chuyển sang pandas datetime không timezone, không tự gán UTC hoặc giờ Việt Nam. Theo yêu cầu Task 3, Timestamp lỗi thành `NaT`, có `invalid_timestamp` và `timestamp_error`, giữ dòng và giá trị `Timestamp_raw`; thay quy ước báo ValueError cho lỗi Timestamp của Task 1.
- Normalizer trả bản sao, sort ổn định theo `(Timestamp, record_index)`, giữ nguyên `id`, khóa và raw. Không tính lại record_index sau sort.
- Loader chuyển `Attachments`, `Size`, `Size_before`, `Size_after`, `Level` (nếu có) sang `Float64` nullable, đồng thời giữ chuỗi nguồn trong `<column>_raw`. Không điền 0 mặc định. Parse lỗi/nonfinite thành `pd.NA`, giữ raw và báo `numeric_issues`; số âm được giữ nguyên, có cờ `has_numeric_issue`, không tự sửa thành kích thước hợp lệ. `Anomaly` giữ string tùy chọn, chỉ diễn giải nhãn ở bước đánh giá.
- Chưa gộp các user như `root`/`root(uid=0)` nếu chưa có mapping xác minh. `Level` là dữ liệu nguồn, không phải severity của ứng dụng.

## API công khai

Kiểu dùng chung nằm tại `preprocessing/contracts.py`. Import module từ root repo.

| Module | Hàm | Trách nhiệm |
|---|---|---|
| `preprocessing.log_loader` | `load_logs(csv_path: str \| os.PathLike \| BinaryIO, *, encoding: str = "utf-8-sig", on_bad_lines: Literal["error", "skip"] = "error") -> pd.DataFrame` | Đọc đường dẫn/upload nhị phân; giữ raw, thêm khóa/record_index; báo cáo ở `df.attrs["load_report"]` |
| `preprocessing.log_normalizer` | `normalize_logs(logs: pd.DataFrame, *, file_sha256: str \| None = None) -> pd.DataFrame` | Trả bản sao event chuẩn hóa; giữ raw/khóa, gắn cờ thời gian lỗi; chỉ cần hash khi đầu vào chưa có khóa |
| `preprocessing.log_normalizer` | `normalize(df, *, file_sha256=None) -> pd.DataFrame` | Alias cùng function object với normalize_logs, dùng chung train/inference |
| `preprocessing.normalized_io` | `save_normalized_logs(logs, path) -> dict` / `read_normalized_logs(path) -> pd.DataFrame` | CSV chuẩn hóa + sidecar checksum/kiểu/attrs; giữ khóa file nguồn gốc |
| `detection.rule_engine` | `detect_rules(logs: pd.DataFrame, *, config: RuleConfig \| str \| Path \| None = None, report: dict \| None = None) -> list[Alert]` | Chạy rule theo JSON/cấu hình/default; điền report khi caller truyền; không sửa logs/config |
| `detection.rule_engine` | `load_rule_config(path: str \| Path \| None = None) -> RuleConfig` | Đọc/validate JSON, mặc định `detection/rules.json` |
| `detection.rule_engine` | `alerts_to_dataframe(alerts: list[Alert]) -> pd.DataFrame` | Giữ thứ tự cột và schema cả khi danh sách alert rỗng |
| `detection.correlation` | `correlate(logs: pd.DataFrame, alerts=None, *, config: CorrelationConfig \| None = None, as_of=None, report: dict \| None = None) -> pd.DataFrame` | Nhóm User/Agent, fixed window + inactivity gap; có snapshot lịch sử |
| `detection.correlation` | `get_timeline(logs: pd.DataFrame, group_id: str, alerts=None, *, config=None, as_of=None) -> pd.DataFrame` | Timeline nguồn theo thời gian, raw giữ nguyên, có has_alert/rule_ids |
| `detection.correlation` | `correlate_events(logs, alerts, *, config, as_of=None) -> list[Correlation]` | Adapter tên cũ: một snapshot cho mỗi nhóm, anchor cuối nhóm; không phải rolling window từng event |
| `detection.severity` | `assign_severity(alerts: list[Alert], correlations=None, ml_results=None, *, events=None, config=None) -> list[Alert]` | Atomic có ưu tiên/reason mới; correlations cần events; ML luôn bỏ qua ở Task 7 |
| `detection.ml_engine` | `predict(df: pd.DataFrame, model_name: str = "random_forest_behavioral.joblib", threshold: float = 0.52) -> pd.DataFrame` | API inference hiện có của Ngọc; chưa tích hợp vào pipeline rule-based. `predict_logs`/list[MLResult] là đề xuất cũ, không phải hàm đã triển khai |

`RuleConfig` đầy đủ có `schema_version="spedia.rules.v1"`, `rules: list[RuleDefinition]`, tùy chọn `enabled_rule_ids`. Mỗi RuleDefinition chứa rule_id, enabled, condition, params, reason_template, base_severity, severity_reason, rationale. Kiểu cụ thể tại `preprocessing/contracts.py`.

Mặc định dùng enabled trong JSON. Shortcut `{enabled_rule_ids: list[str]}` đọc định nghĩa từ JSON mặc định và chọn chính xác danh sách đó, kể cả rule mặc định tắt; list rỗng nghĩa là không chạy rule. Mã lạ/trùng bị từ chối. Không tự bật toàn bộ ứng viên từ khảo sát.

`CorrelationConfig` có window_seconds, max_gap_seconds, min_events là số nguyên dương; mặc định 900, 300, 1. min_events chỉ lọc danh sách hiển thị, không gán nguy cơ. Nếu chỉ đổi window_seconds mà không truyền gap, gap=min(300, window_seconds). Đây là tham số prototype; không khẳng định tối ưu phát hiện.

Quy ước lỗi: loader báo `FileNotFoundError`, `LogEncodingError` (kế thừa `UnicodeError`), `LogLoadError` (kế thừa `ValueError`) tương ứng thiếu file, encoding lỗi, schema/CSV lỗi; hai exception riêng có `.report`. Các module khác báo `ValueError` cho đầu vào không hợp lệ. Không nuốt lỗi rồi trả danh sách rỗng. Rule thiếu cả cột phụ thuộc khi đang bật phải báo tên cột/rule; ô trống trong cột thì bỏ qua điều kiện không đánh giá được và đếm trong báo cáo. Không coi missing là đáng ngờ.

### Chi tiết loader sau Task 2

- Đường dẫn đọc byte gốc. Upload nhận `getvalue()` như Streamlit UploadedFile, hoặc binary stream hỗ trợ read/seek/tell. Đọc toàn bộ file từ đầu, giữ vị trí cursor và không đóng stream. Không nhận text stream vì không còn byte nguồn để định danh chính xác.
- UTF-8/BOM mặc định; muốn encoding khác phải chỉ định, không tự fallback. Không sửa tên header để che lỗi schema. Cấm header trùng/rỗng hoặc trùng metadata loader (`source_row_id`, `record_index`, `has_numeric_issue`, các cột số `_raw`).
- Dòng rỗng vật lý bị bỏ qua, đếm riêng `blank_lines_ignored`, không tăng record_index; thống nhất cách đếm bản ghi của khảo sát Task 1. Field nhiều dòng vẫn là một record.
- Mặc định `on_bad_lines="error"`: dừng và báo vị trí/lý do khi số field sai hoặc field bắt buộc rỗng (ngoại trừ User). `skip` là opt-in; chỉ bỏ các record lỗi phục hồi được và ghi `skipped_records`. Không đánh lại record_index, nên có thể có khoảng trống ở các dòng bị bỏ.
- Lỗi quoting khiến không xác định được ranh giới bản ghi luôn báo lỗi, kể cả ở chế độ skip. CSV không còn record hợp lệ luôn báo lỗi.
- Các cột nguồn được ép pandas string trước xử lý riêng. User rỗng/whitespace thành `pd.NA`, không gộp alias. Raw log rỗng vẫn giữ `""`; nếu thiếu hẳn cột raw tùy chọn thì thêm cột nullable string, không bịa nội dung. Giữ cột nguồn chưa biết và các dòng trùng id. Timestamp còn string, việc parse/sort thuộc normalizer.
- `load_report` có `status`, `encoding`, `file_sha256`, `on_bad_lines`, `rows_read`, `rows_loaded`, `rows_skipped`, `missing_columns`, `blank_lines_ignored`, `skipped_records`, `numeric_issues`, `duplicate_id_rows`. Khi thành công: `rows_read = rows_loaded + rows_skipped`, không tính dòng trống vật lý. Trên exception, số đếm là phần đã đọc trước khi dừng, không phải tổng file; lỗi quoting dang dở nằm riêng trong `unrecoverable_record`.
- Báo cáo cung cấp metadata để caller hiển thị/lưu, loader không tự ghi stdout hoặc ghi đè dataset. Dashboard có thể gọi `load_logs(uploaded_file)` và hiển thị `df.attrs["load_report"]` khi tích hợp.

### Schema event sau Task 3

API: `events = normalize_logs(load_logs(source))`. Không sửa DataFrame đầu vào hoặc metadata của nó. `load_report` được giữ; thêm `events.attrs["normalization_report"]`, schema version `spedia.events.v1`.

Các cột event lõi có thứ tự cố định, định nghĩa tại `preprocessing/log_normalizer.py::EVENT_COLUMNS`:

| Cột | Kiểu/quy ước |
|---|---|
| `source_row_id` | Nullable string nhưng không chấp nhận giá trị thiếu/trống/trùng; giữ nguyên khóa đã có |
| `record_index` | int64 không âm, duy nhất trong file; không đánh lại sau sort/filter |
| `id` | ID nguồn, không ghi đè hoặc dùng làm khóa nội bộ |
| `Timestamp` | datetime64[ns] naive; `NaT` nếu thiếu/sai định dạng/ngày không hợp lệ/ngoài miền ns |
| `Activity`, `Action`, `Decoder_name`, `User`, `Agent_name` | Pandas string; strip + casefold; rỗng thành pd.NA; không dịch Action hoặc gộp alias danh tính |
| `hour` | Int64 nullable, 0..23; thiếu khi Timestamp lỗi |
| `day_of_week` | Int64 nullable, Monday=0..Sunday=6; thiếu khi Timestamp lỗi |
| `date` | Python datetime.date (dtype object), NaT khi Timestamp lỗi; không gắn timezone |
| `invalid_timestamp` | bool; phải được detector/correlation kiểm tra trước khi dùng thứ tự thời gian |
| `timestamp_error` | Nullable string: missing_timestamp, invalid_format, invalid_datetime hoặc pd.NA |
| `Full_log`, `Description`, `Content` | Giữ nguyên giá trị/dtype nguồn; thiếu hẳn cột thì thêm nullable string |

Giữ mọi cột bổ sung, nhãn tham chiếu, kiểu số và cờ chất lượng từ loader. Thêm `Timestamp_raw`, `Activity_raw`, `Action_raw`, `Decoder_name_raw`, `User_raw`, `Agent_name_raw` để giữ chính xác nguồn trước khi chuẩn hóa; không biến đổi ba raw log field. Không tự diễn giải `URL accedida` thành tên action khác, chỉ chuẩn hóa thành `url accedida`.

Sắp tăng theo `(Timestamp, record_index)`, giữ record_index và source_row_id gốc. Dòng `NaT` nằm cuối theo record_index; vị trí cuối chỉ để hiển thị/lưu, không ngụ ý đây là sự kiện mới nhất. Correlation phải loại khỏi phép tính thời gian những dòng `invalid_timestamp=True` và báo giới hạn, không tự điền thời gian hiện tại hay dùng chúng như sự kiện tương lai.

Nếu chưa có `source_row_id`, tạo từ `file_sha256` được truyền hoặc `load_report.file_sha256`, định dạng SHA-256 64 hex thường. Nếu chưa có record_index, tạo từ thứ tự đầu vào trước sort. Caller đưa DataFrame trực tiếp phải giữ đúng thứ tự record gốc; normalizer không thể khôi phục vị trí gốc sau khi caller đã filter/sort mà làm mất metadata. Không hash nội dung chuẩn hóa hoặc Anomaly để bịa namespace. Khóa hiện có không hợp lệ phải báo ValueError, không tự sửa.

Normalizer xử lý một file tại một thời điểm (record_index duy nhất), sau đó mới ghép event nhiều file nếu cần. Metadata/derived column trùng tên ở đầu vào chưa chuẩn hóa bị từ chối để không ghi đè. Khi chạy lại trên output có schema version tương ứng, dùng các cột raw đã lưu để đảm bảo idempotence; không tạo chuỗi `_raw_raw`.

`normalization_report` có số dòng vào/ra, rows_dropped=0, số Timestamp lỗi, danh sách source_row_id/record_index/giá trị/lý do lỗi, thứ tự sort, quy ước timezone và thứ trong tuần. Chuẩn hóa chuỗi là quy tắc so khớp, không xác minh hai account khác hoa/thường là cùng danh tính; giữ `_raw` để điều tra.

Bổ sung Task 3 ngày 22/11/2026: bản chuẩn hóa dùng chung đã xuất tại `data/normalized_logs.csv` (72.250 × 43) và mẫu `data/normalized_logs_sample.csv` (1.000 × 43), mỗi file đi cùng `.schema.json`. Đọc bằng read_normalized_logs, không đưa qua raw loader hoặc tạo lại source_row_id bằng hash file xuất. Tài liệu đủ 43 cột và phân loại giữ nguyên/thay đổi/thêm mới nằm ở `docs/EVENT_SCHEMA.md`. Mẫu dành dựng dashboard, không phải lịch sử đủ để đánh giá rule/correlation. normalize và normalize_logs là cùng hàm, inference không yêu cầu Anomaly.

## Cấu trúc Alert

Tất cả field đều bắt buộc có key; `None` chỉ ở các field ghi nullable:

| Field | Kiểu | Ý nghĩa |
|---|---|---|
| `alert_id` | `str` | `<source_row_id>:<rule_id>`; mỗi rule tối đa một alert trên một dòng |
| `source_row_id` | `str` | Khóa nối về sự kiện gốc |
| `timestamp` | `str` | ISO 8601 millisecond, chưa timezone, từ Timestamp đã parse |
| `user` | `str \| None` | User nguồn, không đoán danh tính |
| `agent`, `activity` | `str` | Ngữ cảnh nguồn; Activity tự nó không phải bằng chứng tấn công |
| `rule_id`, `reason` | `str` | Rule ổn định và giải thích điều kiện khớp cụ thể |
| `evidence` | `dict[str, str \| None]` | Field/giá trị nguồn thực sự dùng; raw giữ nguyên, không chứa Anomaly |
| `severity` | `LOW \| MEDIUM \| HIGH \| CRITICAL \| None` | Task 4 điền base_severity từ cấu hình; module severity tổng hợp có thể cập nhật ở task sau |
| `severity_reason` | `str \| None` | Task 4 điền lý do mức ưu tiên gốc, không để trống |

Severity là **mức ưu tiên xử lý của prototype, không phải tác động đã xác minh**. Không đồng nhất `Level` với severity. Lệnh quản trị, tool mạng, archive hoặc tên Activity tự nó không đủ kết luận tấn công.

### Rule Engine sau Task 4

- Đầu vào là event đã chuẩn hóa: Timestamp datetime naive, khóa không rỗng/trùng, record_index nguyên không âm và duy nhất. Cột lõi: Timestamp, User, Agent_name, Activity, Action, source_row_id, record_index. Thêm Command cho command rule, Path cho file rule, Url cho HTTP rule nếu đang bật; không cần Anomaly/Level.
- JSON chỉ chọn các condition đã triển khai: command_in, file_path_change, http_ip_host, auth_failure_window. Không eval biểu thức từ config. Kiểm tra ID, bool enabled, priority, params, regex, mẫu reason; reason phải có matched_field và matched_value. Ngưỡng/cửa sổ phải là số nguyên dương.
- Rule mặc định bật: CMD_NMAP, CMD_JOHN, CMD_MSFCONSOLE, FILE_CONFIG_CHANGE, HTTP_IP_HOST, AUTH_FAILURE_WINDOW. CMD_NETCAT có triển khai nhưng mặc định tắt do nhiễu. Không bật rule flag.txt/đuôi archive/HTTP traversal từ các ứng viên yếu hoặc không có mẫu.
- Command so basename khớp cả tên và Action thực thi. File đòi hỏi cả Path theo nhóm cấu hình và Action thay đổi. HTTP cần Action truy cập URL và hostname IPv4/IPv6 literal trong URL HTTP(S) hợp lệ. Activity chỉ cung cấp ngữ cảnh alert, không tham gia kết luận.
- Auth được bật vì Task 1 xác nhận failure rõ. Signal từ Action chính xác hoặc regex ngữ cảnh auth trong Action/Description/Full_log, không dùng Content. Description/Full_log thiếu cả cột thì được ghi missing_optional_signal_columns; Action lõi vẫn bắt buộc.
- Auth đếm các dòng failure theo (User, Agent_name) trong cửa sổ đóng `[t-window_seconds, t]`. Chỉ đến anchor theo Timestamp/record_index, kể cả timestamp trùng; threshold/window mặc định 3/300s, cấu hình được. Không yêu cầu failure liên tiếp và login thành công không reset cửa sổ. Mỗi dòng Multiple failed logins chỉ tính một dòng quan sát, không suy ra số lần thử.
- Mỗi failure đạt ngưỡng sinh một alert tại anchor, không gộp thành một incident hoặc khẳng định brute force. User trống thì không tham gia đếm, không thay bằng anonymous/unknown. Agent khác nhau không được gộp chỉ vì cùng User.
- Timestamp NaT hoặc invalid_timestamp=True bị loại khỏi mọi điều kiện vì hợp đồng alert yêu cầu timestamp hợp lệ; báo rows_invalid_time, không sửa/xóa event nguồn. Thiếu giá trị Agent_name/Activity cũng bị bỏ qua có đếm rows_missing_context.
- Vector hóa bằng pandas masks, str methods và groupby rolling. URL chỉ parse một lần trên mỗi giá trị khác nhau; Python loop cuối chỉ serialize các alert khớp. Engine không đọc Anomaly/Level, không thay raw và không fit điều kiện theo nhãn.
- report chứa status, rows_input, missing_columns, disabled_rule_ids, số dòng không đủ ngữ cảnh/thời gian, kết quả/thời gian từng rule, alerts_count và elapsed_seconds. Trên lỗi, report.status=error và exception vẫn được ném. elapsed_seconds chỉ đo detect_rules, không đo loader/normalizer/export.
- Alert có 11 field đúng TypedDict; evidence chứa trường/giá trị khớp, raw log đang có và tham số cửa sổ khi cần. alerts_to_dataframe giữ timestamp ISO string, không tự gán timezone. Một event có thể có nhiều alert với alert_id khác rule_id.

### Điều chỉnh Task 5 và schema bàn giao v1.0

- Command params hỗ trợ `case_sensitive` (bool, mặc định true cho Linux); không casefold tên executable khi chọn true. Action vẫn so trên dạng chuẩn hóa. History và lý do tại `docs/RULE_CHANGELOG.md`.
- File params hỗ trợ `exclude_modified_raw_regex`: khi cấu hình thì Full_log là cột phụ thuộc; chỉ loại Action=file modified có raw xác nhận đổi mtime/ctime đơn thuần. Không loại added/deleted hoặc raw thiếu. Cấu hình hiện có 851 alert file thay vì 1.211; tổng atomic 1.301.
- `detection.alert_aggregation.merge_alerts(alerts: list[Alert]) -> list[MergedAlert]`: một event/source_row_id, rule_ids sort duy nhất, rule_matches giữ đủ evidence/reason, severity=max base priority. Bản gửi lặp chính xác cùng source/rule được bỏ, nội dung mâu thuẫn báo lỗi; không gộp ID khác nhau chỉ vì raw giống nhau.
- `merged_alerts_to_dataframe(alerts)` trả 12 cột cố định; rule_ids/rule_matches là list, xuất CSV thì serialize JSON. Atomic API 11 field Task 4 giữ nguyên; dashboard nên dùng event alert để tránh nhiều dòng trên cùng sự kiện.
- Schema v1.0 là giao diện technical freeze, có kiểm tra hash. Thay đổi phá vỡ field/kiểu/ngữ nghĩa cần phiên bản mới. `validate_atomic_alert`/`validate_merged_alert` kiểm tra cả khóa, lịch và invariant gộp ngoài cấu trúc JSON.
- Đánh giá nhãn ở `evaluation/` riêng biệt: precision=TP/(TP+FP), recall=TP/(TP+FN) trên toàn bộ event nhãn 1, đếm event duy nhất. Label thiếu/lạ loại khỏi mẫu số và báo rõ; không điền thành 0. Disabled rule chỉ chẩn đoán riêng, không nhập production union.
- Không dùng bảng metric để tự tối ưu rule. Cấu hình và mẫu blind được hash trước chấm nhãn; notes kỹ thuật tách khỏi TP/FP theo nhãn. Xem `reports/rule_validation/` và `docs/RULE_ENGINE_LIMITATIONS.md`.

## Correlation nhân quả

Task 6 dùng nhóm trong **fixed window** `[bucket_start, bucket_end)` căn theo epoch của đồng hồ nguồn naive, kết hợp inactivity gap. Không dùng nhãn hoặc trạng thái alert để tạo membership; nhóm cả event chưa có cảnh báo.

- Khóa chính User, khóa phụ Agent_name; không nối hai agent chỉ vì cùng user. Missing User/Agent/Datetime bị loại khỏi phép gán nhóm, có số đếm riêng; không gộp user thiếu thành unknown.
- Sort Timestamp + record_index trước khi chia. Trong mỗi User/Agent/bucket, dùng groupby.diff để tìm gap, gap > max_gap_seconds thì tách (bằng ngưỡng chưa tách); cumsum tạo segment, transform(first) lấy source_row_id đầu làm định danh.
- group_id=`corr:v1:w{window_seconds}:g{max_gap_seconds}:<source_row_id đầu nhóm>`. Không dùng thứ tự nhóm/ngroup để tránh renumber khi user mới xuất hiện. Cùng source_row_id không thuộc hai nhóm.
- Cửa sổ cố định có thể tách hai event rất gần nhau ở hai phía biên, khác sliding window và khác thời lượng tính từ event đầu. Đây là lựa chọn minh bạch để vector hóa và có nhóm hữu hạn/nhân quả; không gọi đó là cùng một khái niệm với auth rolling 300s.

`correlate` trả DataFrame gồm group_id, key={user,agent}, user, agent, start_time, end_time, event_count, activities, alert_count, rule_match_count, rule_ids, source_row_ids. start/end là thời điểm event đầu/cuối thực tế; activities duy nhất theo thứ tự xuất hiện, rule_ids sort, source_row_ids theo Timestamp/record_index.

- alert_count là số event nguồn có ít nhất một alert; rule_match_count là số cặp source_row_id/rule_id duy nhất. Atomic hoặc merged alert cho cùng kết quả, bản gửi lặp không nhân count.
- alerts=None nghĩa chưa chạy detector, counts nullable; alerts=[] nghĩa đã chạy không có alert, counts=0. Báo cáo có detector_state. Alert phải nối về event đã biết; metadata timestamp/user/agent/activity nếu được cung cấp phải khớp. Nhận list atomic/merged hoặc DataFrame; rule_ids của merged phải là list đã decode JSON.
- Group summary đang mở được phép tăng event_count/end_time khi thêm event mới vào cùng nhóm. **Mã nhóm/membership của event cũ không đổi khi append event tương lai**, với cùng config và khóa nguồn ổn định.
- Muốn toàn bộ kết quả lịch sử bất biến, truyền `as_of=(Timestamp, record_index)` cho cả correlate và get_timeline. Chỉ dùng tuple không lớn hơn anchor, kể cả timestamp bằng nhau. as_of chỉ thời gian bao gồm tất cả event tại thời gian đó; dùng tuple để phân thứ tự cùng timestamp.
- Append-only không bao gồm late insertion trước anchor, sửa event cũ, đổi config hoặc load lại file đã đổi byte làm namespace SHA-256 đổi. Các trường hợp đó cần rebuild/phiên bản mới. Không tuyên bố group summary live bất biến khi số event thực tế đã tăng.

get_timeline trả event nguồn tăng theo thời gian, raw không đổi, thêm group_id, has_alert (nullable boolean), alert_count (0/1 khi đã chạy), rule_match_count, rule_ids, alerts_evaluated. Bỏ cột Anomaly khỏi output. Group không tồn tại trong snapshot/config/min_events thì báo ValueError. Dùng cùng as_of để mở đúng snapshot đã lưu.

Report nằm ở groups.attrs["correlation_report"] hoặc dict caller truyền, gồm số dòng input/visible/grouped, missing user/agent/time, min_events bị ẩn, số group, alert event không đủ điều kiện gán nhóm, config, cutoff và thời gian xử lý. Các số loại thiếu có thể chồng lấp, dùng rows_excluded_unique nếu cần tổng duy nhất.

Adapter correlate_events giữ các field Correlation đề xuất cũ, lấy anchor là event cuối nhìn thấy trong nhóm và các thời điểm đầu/cuối thực tế; caller mới nên dùng correlate/get_timeline. Chi tiết và ví dụ tích hợp tại docs/CORRELATION_API.md.

## Luồng và trạng thái tích hợp

Task 8: `detection.pipeline.run_detection_pipeline(df_normalized, *, severity_config=None) -> PipelineResult` trả detected_logs, atomic_alerts, alerts, alert_table, groups, report và status. `dashboard.service.run_upload_pipeline(source)` thêm loader/normalizer cho upload. Khi lỗi, PipelineError có report/status/stage; zero alert thành công không phải error. `data/detected_logs.csv` thêm rule_ids/alert_count/group_id/severity hiện tại theo source_row_id, đọc bằng preprocessing.detected_io.read_detected_logs. Chi tiết tại [PIPELINE_API.md](PIPELINE_API.md). Merged/prioritized trong bộ nhớ do pipeline trả là dữ liệu dashboard; bảng data/alerts.csv đóng băng Task 5 giữ nguyên.

Task 7: `assign_severity` nhận atomic và events chuẩn hóa để tính prefix nhóm nhân quả, trả atomic sao chép có severity/severity_reason; sau đó merge_alerts tạo bảng merged hợp lệ. `ml_results=None` là chỗ mở rộng, luôn bị bỏ qua trong phiên bản này. Cấu hình ngữ cảnh nằm ở `detection/severity_policy.json`, mức gốc lấy từ rules.json; xem [SEVERITY_POLICY.md](SEVERITY_POLICY.md). Kết quả audit/chấm riêng ở reports/severity_assignment, không ghi đè bảng đóng băng data/alerts.csv.

`CSV -> loader -> normalizer -> rules -> correlation -> severity -> dashboard`.

ML là nhánh từ dữ liệu chuẩn hóa. Cách ghép ML/rule cần nhóm xác nhận, chưa tự đưa score ML vào severity. Backend `predict` hiện trả DataFrame gồm source_row_id, timestamp, user, agent, activity, action, predicted_label và anomaly_score; score là xác suất lớp 1 từ model, threshold mặc định 0.52. TypedDict `MLResult` là hợp đồng đề xuất cho adapter tích hợp, chưa phải kiểu trả về của hàm predict. Ngọc cần xác nhận ngữ nghĩa score, threshold và khả năng dùng ngoài dataset trước khi tích hợp.

Dashboard phân biệt `not_run`, `success`, `error`. Chỉ `success` và danh sách alert rỗng mới có nghĩa không có cảnh báo. Nhãn tham chiếu tách riêng cho đánh giá. Train/test chia theo thời gian, fit preprocessing học từ dữ liệu chỉ trên train.

## Quyết định khảo sát và phần chờ nhóm

- Có tín hiệu rõ cho ứng viên `AUTH_FAILURE`, gồm PAM/sudo/FTP/SSH/login. Không gọi tất cả là SSH failure hoặc brute force. 216/330 dòng failure thiếu User, ảnh hưởng correlation theo user.
- Predicate, số khớp và trạng thái từng ứng viên nằm trong `reports/schema_profiling/candidate_rules.csv`. Đây là tần suất khớp sơ bộ, không phải số tấn công hoặc metric chất lượng.
- Nhóm cần xác nhận schema, row ID, alert/API, chủ sở hữu module, rule bật, cửa sổ/ngưỡng correlation, mapping severity, ngữ nghĩa ML score và phiên bản môi trường chung.
- Task 1 cung cấp khảo sát và hợp đồng để review; xác nhận của con người chưa diễn ra.

## Artifact dùng chung bổ sung Task 4–6

Bảng chính `data/alerts.csv` là merged alert v1.0 (12 cột); atomic 11 cột nằm riêng tại `data/alerts_atomic.csv`. Bảng nhóm chính là `data/event_groups.csv`. Mỗi CSV kèm `.schema.json`, đọc bằng `detection.shared_output_io.read_alerts/read_atomic_alerts/read_event_groups`; không truyền nguyên chuỗi JSON từ pd.read_csv vào correlate/get_timeline. API ghi tương ứng là save_alerts/save_atomic_alerts/save_event_groups; tất cả có đường dẫn mặc định như trên. Tạo lại: `python -m detection.export_shared_outputs`. Xem [SHARED_OUTPUTS.md](SHARED_OUTPUTS.md) về kiểu trả về, kiểm chứng và snapshot nhân quả. Đây là bổ sung artifact/IO, không thay đổi alert schema đóng băng hoặc cấu hình rule. Trạng thái Tuấn xác nhận vẫn pending.
