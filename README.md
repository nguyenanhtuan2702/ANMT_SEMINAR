# AI Security Log Analyzer
Đồ án An ninh máy tính: phân tích nhật ký SPEDIA bằng luật và Machine Learning.

## Trạng thái bộ khung
Đã có giao diện Streamlit: upload CSV, kiểm tra các cột hiển thị cần thiết, thống kê và lọc theo Activity.
Chưa có chuẩn hóa nghiệp vụ, phát hiện, mô hình ML, correlation hoặc severity. Các file tương ứng là chỗ dành sẵn để từng thành viên triển khai.

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
Cài Python 3.11 và Git nếu máy chưa có. Mở terminal tại thư mục chứa README.md.
Không cần activate môi trường, dùng trực tiếp Python của .venv:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Chọn file CSV trên giao diện. Có thể đặt dataset đã có vào data/raw/.
Không cần cài thư viện để chỉ push bộ khung lên Git.
requirements.txt chỉ chứa thư viện của giao diện hiện tại. Ngọc bổ sung thư viện ML và nhóm chốt phiên bản sau khi kiểm thử tích hợp.

## Push lần đầu lên GitHub
Tạo repository rỗng (không tạo README, license hoặc .gitignore trên GitHub).
Giải nén rồi mở PowerShell ngay trong thư mục AI-Security-Log-Analyzer.
Thay URL bên dưới bằng URL repo thật của nhóm trước khi chạy lệnh remote.

```powershell
git init
git branch -M main
git add .
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
Không đẩy .venv, mật khẩu, dataset hoặc model nặng. .gitignore đã bỏ qua các mục tương ứng.
Git không lưu thư mục trống nên các thư mục dự phòng có .gitkeep.

## Bước tiếp theo
1. Đọc docs/PHAN_CONG.md và chốt docs/INTEGRATION_CONTRACT.md cùng nhóm.
2. Tuấn bổ sung lọc thời gian/user/agent và chi tiết sự kiện.
3. Thọ và Ngọc bàn giao module cùng ví dụ đầu ra; Tuấn nối vào app.
4. Kiểm thử với dataset thật, ghi kết quả và viết báo cáo.
