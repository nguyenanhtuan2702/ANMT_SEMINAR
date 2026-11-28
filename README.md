# AI Security Log Analyzer

Ứng dụng Streamlit tiếp nhận CSV, chuẩn hóa và giữ log gốc, chạy Machine
Learning cùng Rule Engine, nhóm sự kiện theo thời gian, gán severity có lý do,
và hiển thị cảnh báo/timeline để analyst rà soát.

## Cài đặt và chạy trên Windows

### 1. Tải mã nguồn

**Clone bằng Git:** mở PowerShell tại thư mục muốn lưu project:

```powershell
git clone --branch feature/ml-dashboard-integration https://github.com/nguyenanhtuan2702/ANMT_SEMINAR.git
cd ANMT_SEMINAR
```

Sau khi nhánh tích hợp được merge vào `main`, có thể clone mặc định bằng:

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

Đảm bảo thư mục `models/artifacts/` có các file:

- `logistic_regression.joblib`
- `random_forest.joblib`
- `random_forest_behavioral.joblib`

Các model là cần thiết để chạy dự đoán. Nếu thiếu, hãy tải lại mã nguồn từ nhánh
đã có các artifacts này hoặc yêu cầu nhóm cung cấp chúng.

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

1. Tải CSV SPEDIA có các trường nền `Timestamp`, `User`, `Agent_name`,
   `Activity`, `Action`, `Decoder_name`; các rule đang bật cần thêm `Command`,
   `Path`, `Url`, `Full_log` và `Description`.
2. Ứng dụng tạo khóa `source_row_id`, giữ các giá trị raw và chuẩn hóa trường
   phân loại; `Anomaly` là tùy chọn và không làm đầu vào inference.
3. Chọn model và threshold. ML và Rule Engine chạy độc lập; event có thể có
   cảnh báo từ một hoặc cả hai detector.
4. Xem **Tổng quan**, **Sự kiện**, **Cảnh báo**, **Điều tra** và
   **Đánh giá ML**. Tab Điều tra hiển thị group/timeline theo User + Agent.

Rule Engine áp dụng các rule đã mô tả trong `data/processed/DATA.md`. Correlation
dùng fixed window 15 phút và tách nhóm khi khoảng cách giữa hai event lớn hơn
5 phút. Severity kết hợp rule severity, ML corroboration và tín hiệu trong
prefix thời gian; đây là mức ưu tiên rà soát, không phải kết luận sự cố.
Event thiếu Timestamp hợp lệ được giữ lại nhưng không được chấm ML hoặc
correlate.

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

