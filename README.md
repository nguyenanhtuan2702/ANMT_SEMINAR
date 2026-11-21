# AI Security Log Analyzer
Đồ án An ninh máy tính: phân tích nhật ký SPEDIA bằng luật và Machine Learning.

## Trạng thái
Dashboard nhận CSV, chạy ML inference và hiển thị biểu đồ tổng quan/cảnh báo.
Rule Engine, event correlation và severity chưa được tích hợp.

## Phân công
- **Tuấn:** Dashboard & tích hợp.
- **Thọ:** Xử lý log & phát hiện theo luật.
- **Ngọc:** AI/ML & thực nghiệm.
Theo Excel; nhóm cần xác nhận vì PDF hướng dẫn đang đảo vai trò Tuấn/Thọ.

## Cấu trúc
| Thư mục | Nội dung |
|---|---|
| dashboard/ | app.py — giao diện Streamlit |
| preprocessing/ | Loader và normalizer — Thọ |
| detection/ | Rules, correlation, severity — Thọ; ml_engine.py — Ngọc |
| models/ | Huấn luyện và artifacts — Ngọc |
| evaluation/ | Thực nghiệm và đánh giá — Ngọc |
| data/raw/, data/processed/ | Dữ liệu cục bộ, không đưa lên Git |
| tests/ | Kiểm thử module và tích hợp |
| docs/ | Phân công và quy ước tích hợp |
| reports/ | Báo cáo, slide, minh chứng |

## Chạy trên Windows (PowerShell)
Cài Python 3.12.x và Git nếu máy chưa có. Mở terminal tại thư mục chứa README.md.
Không cần activate môi trường, dùng trực tiếp Python của .venv:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Chọn file CSV trên giao diện. CSV phải có các cột `Timestamp`, `User`,
`Agent_name`, `Activity`, `Action` và `Decoder_name`.
`requirements.txt` ghim phiên bản đã dùng để kiểm thử và lưu model.

### Model artifacts
Dashboard cần các model trong `models/artifacts/`. Git ignore thư mục này mặc định,
nên khi đưa nhánh tích hợp lên Git cần thêm rõ các model đang có trong selector:

```powershell
git add -f models/artifacts/logistic_regression.joblib
git add -f models/artifacts/random_forest.joblib
git add -f models/artifacts/random_forest_behavioral.joblib
```

Không cần đưa `isolation_forest.joblib` lên vì dashboard chưa cung cấp lựa chọn đó.
Không đẩy dataset gốc, predictions hoặc file FP/FN có chứa log.

## Push nhánh tích hợp
Trong repo đã clone sẵn, tạo nhánh mới và stage các file tích hợp:

```powershell
git switch -c feature/ml-dashboard-integration
git add dashboard/app.py detection/ml_engine.py requirements.txt tests/test_ml_engine.py
git add reports/ml/model_metrics.csv reports/ml/*_confusion_matrix.png
git add -f models/artifacts/logistic_regression.joblib
git add -f models/artifacts/random_forest.joblib
git add -f models/artifacts/random_forest_behavioral.joblib
git status
git diff --cached --stat
git commit -m "feat: integrate ML inference into dashboard"
git push -u origin feature/ml-dashboard-integration
```

Sau đó mở Pull Request từ `feature/ml-dashboard-integration` vào nhánh chính.
Người khác clone nhánh để chạy thử:

```powershell
git clone --branch feature/ml-dashboard-integration https://github.com/nguyenanhtuan2702/ANMT_SEMINAR.git
cd ANMT_SEMINAR
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

## Push lần đầu lên GitHub
Tạo repository rỗng (không tạo README, license hoặc .gitignore trên GitHub).
Giải nén rồi mở PowerShell ngay trong thư mục AI-Security-Log-Analyzer.
Thay URL bên dưới bằng URL repo thật của nhóm trước khi chạy lệnh remote.

```powershell
git init
git branch -M main
git add .
git add -f models/artifacts/logistic_regression.joblib
git add -f models/artifacts/random_forest.joblib
git add -f models/artifacts/random_forest_behavioral.joblib
git status
git commit -m "chore: initialize security log analyzer scaffold"
git remote add origin https://github.com/TEN_TAI_KHOAN/TEN_REPO.git
git push -u origin main
```

Nếu Git yêu cầu danh tính, đặt tên/email của bạn rồi chạy lại commit:
```powershell
git config user.name "TEN_CUA_BAN"
git config user.email "EMAIL_CUA_BAN"
```

Nếu repo đã có lịch sử: clone repo trước, chép nội dung bộ khung vào repo, xem git status và commit/push; không force push.
Không đẩy .venv, mật khẩu, dataset hoặc file log. Các model trong selector là artifacts cần thiết để người clone chạy inference; thêm chúng bằng `git add -f` như hướng dẫn ở trên.
Git không lưu thư mục trống nên các thư mục dự phòng có .gitkeep.

## Bước tiếp theo
1. Chốt docs/INTEGRATION_CONTRACT.md cùng nhóm.
2. Tích hợp Rule Engine, correlation và severity.
3. Kiểm thử end-to-end với dataset mẫu, ghi kết quả và hoàn thiện báo cáo.
