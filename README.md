# AI Security Log Analyzer

Ứng dụng Streamlit hỗ trợ xem nhật ký an ninh, chạy dự đoán anomaly bằng
Machine Learning và xem biểu đồ tổng quan/cảnh báo.

> Rule Engine, event correlation và severity chưa được tích hợp.

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

1. Tải file CSV ở thanh bên.
2. Chọn model và điều chỉnh ngưỡng anomaly nếu cần.
3. Xem thống kê/biểu đồ ở **Tổng quan**, danh sách ở **Sự kiện**, cảnh báo
   cùng anomaly score ở **Cảnh báo**.
4. Tab **Đánh giá ML** hiển thị metric và confusion matrix đã lưu trong project.

CSV cần có các cột `Timestamp`, `User`, `Agent_name`, `Activity`, `Action`,
`Decoder_name`. Cột `Anomaly` không bắt buộc và không được dùng làm đầu vào
khi dự đoán.

## Chạy kiểm thử

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Xử lý lỗi thường gặp

- **Không tìm thấy model:** kiểm tra các file `.joblib` trong `models/artifacts/`.
- **Thiếu cột CSV:** dùng file có đủ các cột bắt buộc nêu trên.
- **Cổng đang bận:** chạy ứng dụng với `--server.port 8502`.
- **Thay đổi code nhưng chưa thấy trên trình duyệt:** tải lại trang; nếu cần,
  dừng Streamlit bằng `Ctrl+C` rồi chạy lại lệnh khởi động.

## Phát triển

| Thành viên | Phần phụ trách |
|---|---|
| Tuấn | Dashboard và tích hợp |
| Thọ | Loader, normalizer, rules, correlation, severity |
| Ngọc | ML, huấn luyện, inference và đánh giá |

Theo phân công trong bảng Excel; tài liệu hướng dẫn PDF có chỗ ghi đảo vai trò
Tuấn/Thọ nên nhóm cần xác nhận. Xem thêm `docs/PHAN_CONG.md` và
`docs/INTEGRATION_CONTRACT.md`.

Không commit dataset, thông tin bí mật, môi trường `.venv` hoặc log người dùng.
