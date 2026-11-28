# AI Security Log Analyzer

Ứng dụng Streamlit tiếp nhận CSV, chuẩn hóa và giữ log gốc, chạy Rule Engine và
Machine Learning độc lập trên cùng tập sự kiện, nhóm sự kiện theo thời gian,
gán severity theo policy Rule, và hiển thị cảnh báo/timeline để rà soát.

## Cài đặt và chạy trên Windows

### 1. Tải mã nguồn

**Clone bằng Git:** mở PowerShell tại thư mục muốn lưu project:

```powershell
git clone https://github.com/nguyenanhtuan2702/ANMT_SEMINAR.git
cd ANMT_SEMINAR
```

**Hoặc tải ZIP:** vào trang GitHub của repository, chọn **Code → Download ZIP**,
giải nén, rồi mở PowerShell trong thư mục `ANMT_SEMINAR` có chứa file này.

### 2. Cài Python và thư viện

Cần Python **3.12.x**. Kiểm tra bằng:

```powershell
py -3.12 --version
```

Tạo môi trường riêng và cài dependencies:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Kiểm tra model files

Để bật dự đoán ML, cần có các file sau trong `models/artifacts/`:

- `logistic_regression.joblib`
- `random_forest.joblib`
- `random_forest_behavioral.joblib`

Các file model bị Git ignore và có thể không có trong bản clone. Nếu thiếu,
Dashboard vẫn chạy Rules và đánh dấu ML là `Not Evaluated`; hãy lấy artifacts từ
bản bàn giao model của nhóm để bật dự đoán.

### 4. Chạy ứng dụng

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Mở địa chỉ hiện trong terminal, thường là <http://localhost:8501>.
Nếu cổng 8501 đang được sử dụng:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py --server.port 8502
```

### 5. Dùng ứng dụng

1. Tải CSV SPEDIA có các cột bắt buộc `id`, `Timestamp`, `Agent_name`, `User`,
   `Activity`, `Action`. Normalizer bổ sung `Decoder_name` nếu nguồn chưa có;
   các rule đang bật có thể yêu cầu thêm `Command`, `Path`, `Url`, `Full_log`
   hoặc `Description`.
2. Ứng dụng tạo khóa `source_row_id`, giữ các giá trị raw và chuẩn hóa trường
   phân loại; `Anomaly` là tùy chọn và không làm đầu vào inference.
3. Chọn model và threshold. Mặc định mỗi model lấy threshold từ
   `reports/ml/model_thresholds.json`; nếu cấu hình thiếu hoặc sai, Dashboard
   thông báo và dùng fallback `0.52`.
4. Xem **Overview**, **Events**, **Alerts**, **Timeline** và **ML evaluation**.
   Bảng Events có Rule Alert, Severity, ML Prediction và Anomaly Score; bộ lọc
   chỉ tác động cách hiển thị.

Rule Engine áp dụng các rule đã mô tả trong `data/processed/DATA.md`. Correlation
dùng fixed window 15 phút và tách nhóm khi khoảng cách giữa hai event lớn hơn
5 phút. Severity chỉ theo policy Rule và tín hiệu prefix thời gian; ML không
thay đổi Severity, alert schema v1.0 hoặc lý do của Rule. Severity là mức ưu
tiên rà soát, không phải kết luận tác động.

Inference chạy trên toàn bộ event chuẩn hóa trước bộ lọc giao diện. Nếu có
Timestamp không hợp lệ hoặc lỗi artifact/model, Dashboard báo lỗi ML và giữ
nguyên các màn hình Rules; event thiếu kết quả được ghi là `Not Evaluated`,
không bị xem thành `Normal`.

## Huấn luyện lại từ `data/processed`

Đặt gói dữ liệu đã chuẩn hóa trong `data/processed/`, gồm ít nhất
`normalized_logs.csv` và `normalized_logs.schema.json`. Từ thư mục gốc project,
chạy:

```powershell
.\.venv\Scripts\python.exe -m models.train_model
```

Script đọc `normalized_logs.csv` qua `preprocessing/data_bundle.py`, dùng
`Anomaly` làm nhãn mục tiêu, chia dữ liệu theo thời gian thành 64% train,
16% validation và 20% test. Các preprocessing được fit trên train; ngưỡng
được chọn trên validation. Không dùng `Anomaly`, ID, trường raw hay kết quả
rules/severity làm feature. Feature window chỉ đếm sự kiện trước thời điểm
hiện tại.

Sau khi chạy, model trong `models/artifacts/` được cập nhật và các metric,
ngưỡng validation (`model_thresholds.json`), confusion matrix, FP/FN được ghi
vào `reports/ml/`. Dashboard dùng threshold validation làm mặc định riêng
cho từng model; người dùng vẫn có thể điều chỉnh. Chạy kiểm thử trước khi
dùng model mới trên dashboard. Không dùng `detected_logs.csv` làm
nguồn feature huấn luyện vì nó chứa đầu ra detector.

## Chạy kiểm thử

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

