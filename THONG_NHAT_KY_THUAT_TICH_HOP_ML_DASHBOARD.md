# TÀI LIỆU THỐNG NHẤT KỸ THUẬT

## Tích hợp Machine Learning vào Dashboard – AI Security Log Analyzer

| Thuộc tính | Nội dung |
|---|---|
| Dự án | ANMT_SEMINAR – AI Security Log Analyzer |
| Phiên bản tài liệu | 1.0 |
| Ngày lập | 27/11/2026 |
| Trạng thái | Thống nhất hướng tích hợp giữa Thọ, Ngọc và Tuấn; dùng làm căn cứ triển khai và kiểm thử |
| Phạm vi | Chuẩn hóa khóa sự kiện, tích hợp ML inference, hiển thị và so sánh Rule-based với ML trên Dashboard |

---

## 1. Mục tiêu và nguyên tắc thống nhất

Tài liệu này mô tả cách tích hợp kết quả Machine Learning (ML) của Ngọc vào Dashboard do Tuấn phụ trách, trên nền pipeline Log Loader, Normalizer, Rule Engine, Event Correlation và Severity do Thọ triển khai.

Mục tiêu cuối cùng là để Rule-based Detection và ML-based Anomaly Detection cùng phân tích **một tập log đã chuẩn hóa**, có thể đối chiếu kết quả theo từng event thông qua một khóa duy nhất là `source_row_id`.

Nhóm thống nhất các nguyên tắc sau:

1. **Dùng chung `source_row_id`:** ML phải nhận và giữ nguyên khóa được Loader/Normalizer tạo ra; ML không tự tạo một hệ ID khác.
2. **Giữ Rule và ML độc lập:** Rule Engine tiếp tục tạo alert, correlation và severity; ML tạo predicted label và anomaly score.
3. **Không trộn Anomaly Score vào Severity ở phiên bản tích hợp này:** Severity tiếp tục theo policy hiện tại của Thọ. Không thay đổi công thức hoặc schema alert v1.0.
4. **Join kết quả bằng khóa, không bằng vị trí dòng:** Dashboard ghép kết quả ML và Rule theo `source_row_id`, không dùng DataFrame index, số thứ tự hiển thị hoặc `id` nguồn làm khóa nối.
5. **Chạy inference trên toàn bộ dữ liệu chuẩn hóa trước khi lọc giao diện:** Các feature theo cửa sổ thời gian 15 phút cần lịch sử event đầy đủ; filter trên Dashboard chỉ dùng để hiển thị.
6. **Không dùng nhãn tham chiếu làm đầu vào dự đoán:** Cột `Anomaly` chỉ phục vụ đánh giá sau inference, tuyệt đối không đưa vào feature ML, Rule Engine, Correlation hoặc Severity.

### Ngoài phạm vi phiên bản này

- Không thiết kế lại hoặc viết lại Rule Engine, Correlation hay Severity.
- Không tạo một công thức Severity mới kết hợp Rule và ML.
- Không khẳng định ML-only là False Positive hoặc Rule-only là False Negative nếu chưa đối chiếu với nhãn tham chiếu hợp lệ.
- Không huấn luyện lại model trong mỗi lần người dùng tải CSV. Dashboard chỉ nạp model artifact đã được lưu.

---

## 2. Hiện trạng repository làm mốc tích hợp

Các trạng thái dưới đây được đối chiếu từ repository `ANMT_SEMINAR` trong file ZIP ngày 27/11/2026.

| Thành phần | Hiện trạng trong repository |
|---|---|
| Loader / Normalizer | Đã tạo `source_row_id` theo SHA-256 file gốc và `record_index`; Normalizer giữ khóa và sort ổn định theo `(Timestamp, record_index)`. |
| Rule-based pipeline | `dashboard/service.py` gọi `load_logs()` → `normalize()` → `run_detection_pipeline()`. Pipeline trả `detected_logs`, alerts, groups và report. |
| Severity | Đã triển khai policy ưu tiên xử lý prototype. `assign_severity()` hiện bỏ qua ML; Severity không phải mức tác động đã xác minh. |
| ML inference | Đã có `detection/ml_engine.py` với hàm `predict(df, model_name, threshold)`. |
| Model artifacts | Ba file `logistic_regression.joblib`, `random_forest.joblib`, `random_forest_behavioral.joblib` có trong workspace/ZIP snapshot; `models/artifacts/*` bị `.gitignore` nên checkout chỉ từ Git có thể không có. |
| Dashboard | `dashboard/views.py` hiện có Overview, Events, Alerts, Timeline và ML evaluation. Tab ML evaluation hiện thông báo ML chưa chạy; chưa gọi `predict()`. |
| Training script | `models/train_model.py` hiện mới có docstring, chưa có implementation huấn luyện có thể chạy lại. |

### 2.1. Vấn đề ID hiện tại

Trong `detection/ml_engine.py`, `make_source_row_ids()` hiện ưu tiên dùng cột `id` nếu các giá trị không rỗng và duy nhất; nếu không thì tự tạo `row_1`, `row_2`, ... Cách này không thống nhất với khóa của Loader.

Ví dụ cùng một event có thể có:

```text
Rule / Normalizer: <sha256-file>:00000015
ML hiện tại:       row_16
```

Hai kết quả không thể join đáng tin cậy. Cần sửa theo hợp đồng tại mục 3.

### 2.2. Vấn đề tích hợp Dashboard

`dashboard/service.py` hiện chỉ chạy pipeline Rule-based. `dashboard/views.py` chưa gọi `detection.ml_engine.predict()` và chưa có các control inference thực tế. Vì vậy, phần việc của Tuấn là bổ sung ML vào luồng Dashboard hiện tại, không phải xây dựng lại Dashboard từ đầu.

> Đồng bộ tài liệu: README đã được sửa để phản ánh Dashboard Rule-based hiện tại và link tới hợp đồng này. Sau khi hoàn tất tích hợp ML, cần cập nhật README lần nữa theo đúng chức năng đã triển khai.

---

## 3. Hợp đồng dữ liệu dùng chung

### 3.1. Định nghĩa `source_row_id`

Khóa chính thức của một event là:

```text
source_row_id = "<sha256 toàn bộ byte file CSV gốc>:<record_index:08d>"
```

Quy tắc:

- SHA-256 được tính trên toàn bộ byte của file gốc, biểu diễn bằng 64 ký tự hex thường.
- `record_index` là số nguyên bắt đầu từ `0` sau header, đếm **bản ghi CSV**, không đếm dòng vật lý trong file.
- Ví dụ: `a8f3...c921:00000015`.
- Loader tạo `source_row_id` và `record_index` trước khi dữ liệu được sort hoặc filter.
- Normalizer giữ nguyên hai trường này; không tính lại sau sort.
- Hai dòng có cùng `id` nguồn vẫn có `source_row_id` khác nhau nếu vị trí record khác nhau.
- Khác file gốc thì SHA-256 khác, do đó khóa thuộc namespace của file đó.
- Không dùng tên file, đường dẫn file, nội dung đã normalize hoặc nhãn `Anomaly` để tạo lại khóa.

### 3.2. Quy định đối với ML Engine

Sửa `make_source_row_ids()` trong `detection/ml_engine.py` theo các yêu cầu:

1. Bắt buộc đầu vào có cột `source_row_id`.
2. Giữ nguyên giá trị `source_row_id` từ Normalizer.
3. Không fallback sang `id`.
4. Không tự sinh `row_N`.
5. Báo lỗi rõ ràng nếu khóa bị thiếu, rỗng, null hoặc trùng.
6. Không thay đổi hoặc tính lại khóa trong quá trình tạo feature, sort, inference hay trả kết quả.

Mã tham khảo cho phần validation:

```python

def make_source_row_ids(df: pd.DataFrame) -> pd.Series:
    if "source_row_id" not in df.columns:
        raise ValueError(
            "Input ML phải có source_row_id từ Log Loader/Normalizer."
        )

    ids = df["source_row_id"].astype("string")

    if ids.isna().any() or ids.str.strip().eq("").any():
        raise ValueError("source_row_id không được null hoặc rỗng.")

    if ids.duplicated().any():
        raise ValueError("source_row_id phải duy nhất trong một file input.")

    return ids
```

Đoạn mã trên là định hướng validation; Ngọc cần tích hợp và điều chỉnh vào implementation hiện tại, đồng thời cập nhật test.

### 3.3. Đầu vào ML

ML inference nhận DataFrame event đã được Loader/Normalizer xử lý. Các trường sử dụng trong code hiện tại gồm:

| Cột | Vai trò |
|---|---|
| `source_row_id` | Khóa bắt buộc, giữ nguyên để join kết quả. |
| `Timestamp` | Tạo feature `hour`, `day_of_week` và feature theo cửa sổ thời gian. |
| `User` | Feature danh mục và đếm event quá khứ theo User. Giá trị thiếu được xử lý thành `Unknown` ở bước chuẩn bị feature hiện tại. |
| `Agent_name` | Feature danh mục và đếm event quá khứ theo Agent. |
| `Activity` | Feature danh mục. |
| `Action` | Feature danh mục. |
| `Decoder_name` | Feature danh mục; Normalizer cần bảo đảm cột này tồn tại theo schema event. |
| `Anomaly` | Nhãn tham chiếu, không phải feature inference. Có thể không tồn tại trong CSV mới. |

Không thay đổi hợp đồng đầu vào của Loader/Normalizer chỉ để phù hợp với ML. Nếu thiếu trường bắt buộc cho ML hoặc có timestamp không hợp lệ, Dashboard cần thông báo lỗi ML rõ ràng nhưng vẫn giữ kết quả Rule-based nếu pipeline Rule đã chạy thành công.

### 3.4. Feature theo thời gian

ML Engine hiện tạo:

- `hour`
- `day_of_week`
- `User_events_15min_past`
- `Agent_name_events_15min_past`

Các feature đếm 15 phút chỉ sử dụng event trong quá khứ, không tính chính event hiện tại hoặc event tương lai.

Quy định tích hợp:

- Inference chạy trên **toàn bộ DataFrame chuẩn hóa** của file upload.
- Không chạy inference trên DataFrame đã bị filter ở giao diện.
- Không dùng summary cuối nhóm hoặc thông tin tương lai của Event Correlation làm feature cho event cũ.
- Giữ thứ tự nhân quả theo `(Timestamp, record_index)` khi tạo feature. Với timestamp trùng nhau, `record_index` là thứ tự ổn định.
- Timestamp lỗi không được tự điền bằng thời gian hiện tại hoặc tự đưa vào cửa sổ 15 phút. Theo implementation hiện tại, `prepare_ml_input()` sẽ báo lỗi nếu có Timestamp không hợp lệ; Dashboard phải hiển thị lỗi ML và không làm hỏng phần Rule-based.

### 3.5. Đầu ra ML

Hàm hiện có:

```python
from detection.ml_engine import predict

ml_results = predict(
    normalized_events,
    model_name="random_forest_behavioral.joblib",
    threshold=0.52,
)
```

Đầu ra hiện có các cột:

| Cột | Kiểu / ý nghĩa |
|---|---|
| `source_row_id` | Khóa của event nguồn. |
| `timestamp` | Timestamp đã parse. |
| `user` | User. |
| `agent` | Agent. |
| `activity` | Activity. |
| `action` | Action. |
| `predicted_label` | Nhãn dự đoán dạng số: `0` hoặc `1`. |
| `anomaly_score` | Điểm từ `predict_proba()`, nằm trong `[0, 1]`. |

Quy ước hiển thị trên Dashboard:

- `0` → `Normal`.
- `1` → `Anomaly`.
- `anomaly_score` có thể hiển thị dạng số thập phân hoặc phần trăm, nhưng cần ghi rõ đây là score do model trả về.

Ngọc cần xác nhận và ghi vào tài liệu model rằng nhãn `1` tương ứng với `Anomaly`. Code hiện tại lấy cột xác suất `predict_proba()[:, 1]`; cần bảo đảm mapping lớp không bị đảo khi thay artifact. Không chỉ dựa vào thứ tự cột xác suất nếu model được huấn luyện lại với encoding khác.

---

## 4. Hợp đồng Model và Threshold

### 4.1. Danh sách model

Dashboard cung cấp lựa chọn các artifact hiện có:

| Tên hiển thị | Artifact |
|---|---|
| Logistic Regression | `logistic_regression.joblib` |
| Random Forest | `random_forest.joblib` |
| Random Forest Behavioral | `random_forest_behavioral.joblib` |

Mặc định ban đầu:

```text
model_name = random_forest_behavioral.joblib
```

Đây là giá trị mặc định hiện có trong hàm `predict()`, không phải kết luận model này tốt nhất. Báo cáo `reports/ml/model_metrics.csv` hiện có dòng Logistic Regression và Random Forest; không có dòng metric riêng cho Random Forest Behavioral. Do đó không xếp hạng model chỉ dựa vào file metrics hiện tại.

### 4.2. Threshold

Dashboard cung cấp slider với cấu hình:

| Thuộc tính | Giá trị |
|---|---:|
| Minimum | `0.00` |
| Maximum | `1.00` |
| Default | `0.52` |
| Step | `0.01` |

Quy tắc dự đoán hiện tại:

```python
predicted_label = (anomaly_score >= threshold).astype(int)
```

Diễn giải:

- Nếu `anomaly_score >= threshold` → `Anomaly`.
- Nếu `anomaly_score < threshold` → `Normal`.
- Tăng threshold làm điều kiện gắn nhãn Anomaly chặt hơn; giảm threshold làm điều kiện dễ đạt hơn.

`0.52` là giá trị mặc định hiện có trong code, không được mô tả là threshold tối ưu đã được hiệu chỉnh. Việc chọn threshold chính thức cần căn cứ vào tập validation và phân tích precision/recall của Ngọc.

### 4.3. Metadata lần inference

Dashboard cần hiển thị hoặc lưu trong session/report tối thiểu:

- Tên model artifact đang sử dụng.
- Threshold đang sử dụng.
- Số event đầu vào.
- Số event có kết quả inference.
- Trạng thái inference (success/error).
- Nội dung lỗi nếu inference không thành công.

Không bắt buộc thêm các metadata này vào từng dòng CSV output trong phiên bản đầu; có thể giữ trong phần report của lần chạy.

---

## 5. Quy tắc join Rule và ML

### 5.1. Khóa join

Dùng `source_row_id` làm khóa duy nhất:

```python
combined = events.merge(
    ml_results[
        ["source_row_id", "predicted_label", "anomaly_score"]
    ],
    on="source_row_id",
    how="left",
    validate="one_to_one",
)
```

Đây là ví dụ minh họa. Implementation cần kiểm tra trước khi merge:

- `source_row_id` bên event không null/rỗng/trùng.
- `source_row_id` bên ML không null/rỗng/trùng.
- Mọi ML `source_row_id` đều thuộc tập event đầu vào.
- Số kết quả ML phải bằng số event được inference thành công.
- Merge không làm tăng số dòng event.

Không join bằng `id`, DataFrame index, timestamp đơn lẻ hoặc vị trí dòng vì các giá trị này không bảo đảm duy nhất.

### 5.2. Xác định trạng thái Rule

Từ output pipeline hiện tại, event có Rule alert nếu:

- `rule_ids` có ít nhất một phần tử; hoặc
- `source_row_id` xuất hiện trong danh sách `result["alerts"]`.

Khi dùng cột `rule_ids` của `detected_logs`, cần coi danh sách rỗng là không có Rule alert. Severity lấy từ output Rule-based hiện tại và không bị ML ghi đè.

### 5.3. Xác định trạng thái ML

- `is_ml_anomaly = (predicted_label == 1)`.
- `is_rule_alert = True` nếu event có ít nhất một Rule alert.

Tạo nhóm so sánh theo hai cờ trên:

| Nhóm | Điều kiện | Diễn giải |
|---|---|---|
| Both | Rule = Có, ML = Anomaly | Hai phương pháp cùng đánh dấu event. |
| Rule Only | Rule = Có, ML = Normal | Chỉ Rule đánh dấu event. |
| ML Only | Rule = Không, ML = Anomaly | Chỉ ML đánh dấu event. |
| Neither | Rule = Không, ML = Normal | Cả hai phương pháp không đánh dấu event. |

Bốn nhóm trên phải phân hoạch toàn bộ event có kết quả ML hợp lệ; tổng số lượng bốn nhóm phải bằng số event được so sánh.

Nếu inference lỗi hoặc thiếu kết quả cho một phần event, không được tự xem các event chưa có prediction là `Normal` hoặc `Neither`. Phải đánh dấu `Not evaluated` và loại chúng khỏi mẫu số so sánh.

### 5.4. Không diễn giải nhóm bất đồng thành lỗi mô hình

- `ML Only` không tự động có nghĩa Rule False Negative.
- `Rule Only` không tự động có nghĩa ML False Positive.
- `Both` chỉ thể hiện mức độ đồng thuận giữa hai phương pháp, không chứng minh event là tấn công.
- Muốn đánh giá đúng/sai phải đối chiếu với nhãn tham chiếu `Anomaly` hợp lệ và chỉ dùng nhãn ở bước evaluation.

---

## 6. Quy định Severity và Alert

Phiên bản tích hợp này giữ nguyên policy Severity của Thọ.

1. Rule Engine tiếp tục tạo alert theo `detection/rules.json`.
2. Correlation tiếp tục dùng cấu hình và quy tắc hiện tại.
3. Severity tiếp tục lấy theo `detection/severity_policy.json`.
4. ML chỉ trả `predicted_label` và `anomaly_score`.
5. Dashboard hiển thị Severity và Anomaly Score ở hai trường/cột riêng biệt.
6. Không cập nhật `severity`, `severity_reason`, `rule_matches` hoặc alert schema v1.0 bằng kết quả ML.
7. Không truyền ML score vào `assign_severity()` để điều chỉnh mức trong phiên bản này.

Cần giữ nguyên cách diễn giải của tài liệu `docs/SEVERITY_POLICY.md`: Severity hiện là **mức ưu tiên xử lý của prototype**, không phải mức tác động thực tế đã xác minh.

Việc kết hợp ML vào Severity, nếu nhóm muốn thực hiện trong tương lai, phải là một quyết định kỹ thuật riêng, có policy/version mới, test riêng và không âm thầm thay đổi schema/policy hiện tại.

---

## 7. Chức năng Dashboard cần triển khai

### 7.1. Chọn model

Bổ sung `selectbox` cho ba model artifact tại mục ML controls (đề xuất đặt ở sidebar để lựa chọn có hiệu lực cho toàn bộ lần phân tích).

### 7.2. Chọn threshold

Bổ sung `slider` từ `0.00` đến `1.00`, mặc định `0.52`, bước `0.01`. Khi người dùng đổi threshold, Dashboard chạy lại hoặc lấy cache inference tương ứng với threshold mới.

### 7.3. Hiển thị ML Prediction và Anomaly Score

Trong bảng Events, thêm tối thiểu hai trường:

- `ML Prediction`: Normal / Anomaly.
- `Anomaly Score`: score của model.

Trong khu vực ML Evaluation, hiển thị tên model và threshold được dùng ở lần chạy hiện tại.

### 7.4. Bộ lọc sự kiện

Bổ sung filter theo các nhóm:

- `All Events`
- `ML Anomaly Only`
- `Rule Alerts Only`
- `Both Rule and ML`
- `ML Only`
- `Rule Only`

Quy định:

- Filter tác động lên bảng Events và các số đếm liên quan trên giao diện.
- Filter không thay đổi tập dữ liệu đã dùng để chạy Rule hoặc ML.
- Không chạy lại feature engineering trên phần dữ liệu đã filter.
- Các event chưa có kết quả ML phải được phân biệt với Normal.

### 7.5. Khu vực Rule vs ML Comparison

Trong tab `ML evaluation`, bổ sung:

- Tổng số event được đánh giá.
- Số event Rule alert.
- Số event ML dự đoán Anomaly.
- Số event Both.
- Số event Rule Only.
- Số event ML Only.
- Số event Neither.
- Bảng chi tiết cho phép drill-down về event theo `source_row_id`.

Nên có bảng đối chiếu tối thiểu:

| source_row_id | Rule Alert | Severity | ML Prediction | Anomaly Score | Comparison Group |
|---|---|---|---|---:|---|
| Khóa event | Có/Không | LOW/MEDIUM/HIGH/CRITICAL/— | Normal/Anomaly | 0–1 | Both/Rule Only/ML Only/Neither |

Không bắt buộc thêm một tab riêng nếu tab `ML evaluation` hiện tại đáp ứng được các thông tin trên.

### 7.6. Xử lý lỗi

Nếu ML inference thất bại (thiếu artifact, thiếu cột, timestamp lỗi, khóa không hợp lệ hoặc model load lỗi):

- Hiển thị thông báo lỗi ML rõ ràng.
- Không làm sập toàn bộ Dashboard.
- Vẫn cho xem Overview, Events, Alerts và Timeline nếu Rule pipeline đã chạy thành công.
- Không hiển thị số liệu ML cũ từ lần upload/model/threshold trước như thể thuộc lần chạy hiện tại.

---

## 8. Cache và hiệu năng

Dashboard hiện cache Rule pipeline theo nội dung file và hash của rules/policy. Inference ML cần cache độc lập hoặc mở rộng cache nhưng phải có đủ cache key.

Cache key của ML tối thiểu phải phân biệt:

- Nội dung file upload (hoặc SHA-256 file gốc).
- `model_name`.
- `threshold`.
- Phiên bản model artifact (ví dụ `mtime_ns` và `size`, hoặc hash artifact).

Không được trả lại kết quả inference cũ khi người dùng đổi model hoặc threshold. Không cache chỉ theo tên file upload vì hai file khác nhau có thể cùng tên.

Việc thay đổi model/threshold không nên khiến Rule pipeline phải chạy lại nếu raw input và rules/policy không đổi. Có thể giữ kết quả Rule trong cache và chỉ chạy lại ML inference.

---

## 9. Phân công triển khai

| Người phụ trách | Công việc | File/khu vực liên quan | Đầu ra cần bàn giao |
|---|---|---|---|
| **Thọ** | Xác nhận hợp đồng `source_row_id`, schema normalized event và schema alert; hỗ trợ kiểm tra kết quả join; bảo đảm pipeline/Severity không bị thay đổi ngoài phạm vi. | `preprocessing/`, `detection/pipeline.py`, `detection/severity.py`, `docs/INTEGRATION_CONTRACT.md`, `docs/ALERT_SCHEMA_V1.md` | Xác nhận khóa và schema dùng chung; xác nhận regression Rule-based vẫn đúng. |
| **Ngọc** | Sửa ML Engine để nhận khóa từ Normalizer; xác nhận mapping lớp 1 = Anomaly; kiểm tra output/threshold; bổ sung test; cung cấp cách tái lập huấn luyện và thông tin train/test. | `detection/ml_engine.py`, `models/`, `reports/ml/`, `tests/test_ml_engine.py` | `predict()` dùng `source_row_id` gốc; test pass; model metadata/mapping rõ; thông tin hoặc script training có thể tái lập. |
| **Tuấn** | Tích hợp inference vào luồng Dashboard; thêm model selector, threshold, prediction, score, filter, comparison; xử lý lỗi/cache; cập nhật hướng dẫn chạy. | `dashboard/service.py`, `dashboard/views.py`, `dashboard/app.py`, `README.md`, `dashboard/README.md`, `tests/` | Dashboard chạy đồng thời Rule + ML; có bảng và thống kê đối chiếu; hướng dẫn/demo cập nhật đúng code. |
| **Cả nhóm** | Chạy kiểm thử tích hợp trên cùng dataset và xác nhận kết quả cuối. | Toàn repository | Biên bản test end-to-end, ảnh demo và xác nhận các tiêu chí nghiệm thu ở mục 10. |

### 9.1. Chi tiết phần Ngọc cần bàn giao

Trong snapshot hiện tại, `models/train_model.py` chỉ có docstring, chưa có code huấn luyện. Vì vậy, ngoài việc sửa ID và kiểm tra inference, Ngọc cần cung cấp một trong hai hình thức:

- Script huấn luyện có thể chạy lại từ dữ liệu đầu vào đã mô tả; hoặc
- Nếu việc phát hành script không nằm trong phạm vi, tối thiểu phải có tài liệu tái lập: cách tạo train/test, target mapping, feature list, thứ tự preprocessing, phiên bản thư viện, tham số model, metric và cách sinh artifacts.

Báo cáo `reports/ml/model_metrics.csv` hiện liệt kê Logistic Regression và Random Forest; cần ghi rõ tập dữ liệu/tập đánh giá và bổ sung kết quả riêng cho Random Forest Behavioral nếu nhóm dùng model này trong demo.

---

## 10. Trình tự triển khai

Thực hiện theo thứ tự để tránh sửa đi sửa lại giữa các module.

### Bước 1 – Chốt hợp đồng khóa

- Thọ xác nhận định nghĩa `source_row_id` trong `docs/INTEGRATION_CONTRACT.md`.
- Ngọc cập nhật `make_source_row_ids()` để chỉ validate/giữ khóa, không tự sinh ID khác.
- Bổ sung test cho khóa thiếu, rỗng, trùng và khóa hợp lệ.

**Điều kiện qua bước:** cùng một event có cùng `source_row_id` ở normalized events, Rule output và ML output.

### Bước 2 – Chốt hợp đồng ML output

- Xác nhận model artifacts được load đúng.
- Xác nhận class `1` là Anomaly.
- Xác nhận `anomaly_score` nằm trong `[0, 1]`.
- Xác nhận threshold áp dụng theo `score >= threshold`.
- Giữ `Anomaly` khỏi feature input.

**Điều kiện qua bước:** `predict()` trả đúng một kết quả cho mỗi event hợp lệ và giữ khóa gốc.

### Bước 3 – Tích hợp service/cache

- Tuấn gọi ML inference trên DataFrame đã normalize từ lần upload.
- Không thay đổi kết quả pipeline Rule-based.
- Tách cache ML hoặc bổ sung cache key đủ model/threshold/artifact version.
- Xử lý lỗi ML riêng, không làm mất kết quả Rule-based.

**Điều kiện qua bước:** thay model hoặc threshold chỉ làm mới kết quả ML tương ứng; Rule result không bị thay đổi.

### Bước 4 – Tích hợp giao diện

- Thêm model selector và threshold slider.
- Thêm ML Prediction và Anomaly Score vào Events.
- Thêm filter theo nhóm Rule/ML.
- Thêm thống kê Both, Rule Only, ML Only, Neither trong ML evaluation.

**Điều kiện qua bước:** người dùng có thể chọn model/threshold và quan sát kết quả cập nhật đúng.

### Bước 5 – Kiểm thử end-to-end và cập nhật tài liệu

- Chạy cùng một file CSV qua Loader → Normalizer → Rule pipeline và ML inference.
- Xác nhận join không mất hoặc nhân đôi event.
- Kiểm tra các nhóm so sánh có tổng bằng số event có prediction.
- Chạy regression tests cho Rule, Correlation, Severity và Dashboard.
- Cập nhật README và tài liệu hợp đồng theo đúng code sau tích hợp.

---

## 11. Tiêu chí nghiệm thu

| ID | Tiêu chí | Điều kiện đạt |
|---|---|---|
| INT-01 | Dùng chung khóa | ML không tự tạo `row_N`; giữ nguyên `source_row_id` từ Normalizer. |
| INT-02 | Validate khóa | Khóa thiếu/rỗng/trùng phải báo lỗi rõ ràng. |
| INT-03 | Một kết quả mỗi event | Với lần inference thành công trên toàn bộ input hợp lệ, số prediction bằng số event đầu vào. |
| INT-04 | Join đúng | Join Rule/ML bằng `source_row_id`, validate one-to-one và không làm tăng số event. |
| INT-05 | Chọn model | Cả ba artifact được liệt kê có thể chọn và inference thành công trong môi trường dependency tương thích. |
| INT-06 | Chọn threshold | Slider có miền 0–1, mặc định 0.52, step 0.01; label theo score >= threshold. |
| INT-07 | Nhãn dự đoán | Hiển thị Normal/Anomaly; mapping lớp 1 = Anomaly được xác nhận. |
| INT-08 | Anomaly Score | Score hiển thị được, nằm trong [0, 1]. |
| INT-09 | Bộ lọc | Lọc đúng All, ML Anomaly, Rule Alerts, Both, ML Only và Rule Only. |
| INT-10 | Comparison | Both + Rule Only + ML Only + Neither bằng số event có ML prediction. |
| INT-11 | Severity độc lập | ML không làm thay đổi severity/severity_reason/alert schema v1.0. |
| INT-12 | Không leakage | `Anomaly` không được đưa vào feature inference. |
| INT-13 | Feature nhân quả | Inference chạy trên toàn bộ dữ liệu chuẩn hóa; không dùng dữ liệu tương lai hoặc dữ liệu đã filter UI. |
| INT-14 | Xử lý lỗi | ML lỗi không làm Dashboard mất khả năng xem Rule-based results. |
| INT-15 | Cache đúng | Đổi file/model/threshold/artifact version không trả kết quả ML cũ. |
| INT-16 | Regression | Test hiện có của Loader, Normalizer, Rule, Correlation, Severity và Dashboard vẫn đạt. |
| INT-17 | Tài liệu chạy | README mô tả đúng giao diện và lệnh chạy thực tế sau tích hợp. |

---

## 12. Danh sách file dự kiến thay đổi

| File | Người chính | Thay đổi dự kiến |
|---|---|---|
| `detection/ml_engine.py` | Ngọc | Thống nhất `source_row_id`, xác thực class mapping/score/threshold, giữ đầu ra ML ổn định. |
| `tests/test_ml_engine.py` | Ngọc | Bổ sung test khóa hợp lệ/không hợp lệ, threshold, mapping lớp và output. |
| `dashboard/service.py` | Tuấn | Bổ sung bước chạy ML hoặc service gọi inference sau khi có normalized events; không sửa rule pipeline. |
| `dashboard/views.py` | Tuấn | Model selector, threshold, prediction/score, filters và Rule-vs-ML comparison. |
| `tests/test_dashboard.py` và/hoặc test tích hợp mới | Tuấn + Ngọc | Test luồng upload, cache key, join và xử lý lỗi inference. |
| `docs/INTEGRATION_CONTRACT.md` | Tuấn + Thọ + Ngọc | Bổ sung hợp đồng ML và trạng thái tích hợp mới; giữ lịch sử contract cũ khi cần. |
| `README.md` | Tuấn | Cập nhật chức năng ML thực tế, điều kiện đầu vào và cách chạy. |
| `models/train_model.py` và tài liệu ML | Ngọc | Bổ sung khả năng tái lập training hoặc tài liệu tái lập đầy đủ. |

Không bắt buộc phải tạo thêm module Python nếu cấu trúc hiện tại đáp ứng được. Tuy nhiên nên tách phần gọi ML khỏi logic render UI để dễ test.

---

## 13. Checklist xác nhận trước khi merge

- [ ] Ngọc đã sửa `make_source_row_ids()` và test không còn fallback `id`/`row_N`.
- [ ] Thọ đã xác nhận `source_row_id` và normalized schema là nguồn khóa chính thức.
- [ ] Ngọc đã xác nhận `classes_[1]` tương ứng nhãn Anomaly và ghi rõ trong tài liệu model.
- [ ] Các model artifact cần demo load thành công trên môi trường dependency của nhóm.
- [ ] Tuấn đã tích hợp inference sau bước normalize và trước các filter giao diện.
- [ ] Dashboard cho chọn model và threshold.
- [ ] Bảng Events hiển thị ML Prediction và Anomaly Score.
- [ ] Có filter All / ML Anomaly / Rule Alert / Both / ML Only / Rule Only.
- [ ] Có thống kê và bảng Rule-vs-ML Comparison.
- [ ] ML không thay đổi Severity hoặc schema alert v1.0.
- [ ] Trường hợp ML lỗi vẫn xem được kết quả Rule-based.
- [ ] Regression và end-to-end tests đã chạy trên môi trường Python/dependencies thống nhất.
- [ ] README, ảnh demo và báo cáo đã cập nhật.

---

## 14. Tóm tắt quyết định kỹ thuật

| Chủ đề | Quyết định |
|---|---|
| Khóa join | `source_row_id` từ Loader/Normalizer |
| Cách tạo ID trong ML | Không tự tạo; chỉ nhận và validate ID có sẵn |
| Rule Engine | Giữ nguyên |
| ML Engine | Dùng `predict()` hiện có, chuẩn hóa hợp đồng ID và output |
| Model lựa chọn | Logistic Regression / Random Forest / Random Forest Behavioral |
| Model mặc định | `random_forest_behavioral.joblib` |
| Threshold mặc định | `0.52`, điều chỉnh trong khoảng 0–1, step 0.01 |
| Nhãn | `0 = Normal`, `1 = Anomaly` – Ngọc xác nhận mapping trước khi nghiệm thu |
| Anomaly Score | Hiển thị riêng, không đồng nhất với Severity |
| Severity | Giữ nguyên policy Rule-based của Thọ |
| So sánh | Both / Rule Only / ML Only / Neither |
| Cách đánh giá đúng/sai | So với nhãn tham chiếu `Anomaly`, không suy ra từ mức độ đồng thuận Rule-vs-ML |
| Thứ tự tích hợp | Chốt ID → chốt ML output → tích hợp service/cache → Dashboard → end-to-end test |

**Kết luận:** Dashboard sẽ trình bày hai góc nhìn phát hiện độc lập trên cùng một event: Rule-based Detection giải thích bằng rule/evidence và severity; ML-based Detection cung cấp predicted label và anomaly score. `source_row_id` là cầu nối duy nhất giữa hai kết quả. Việc giữ độc lập hai nhánh giúp nhóm so sánh được khả năng phát hiện mà không làm thay đổi logic Rule, Correlation hoặc Severity đã hoàn thành.
