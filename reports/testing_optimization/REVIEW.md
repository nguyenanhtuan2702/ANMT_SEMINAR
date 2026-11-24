# Rà soát lại phần của Thọ

Ngày kiểm tra: 24/11/2026, sau khi đổi tên thư mục báo cáo theo công việc.

## Đối chiếu Task 1–9

| Task | Kết quả đối chiếu |
|---|---|
| 1 — Khảo sát schema | Có hồ sơ 24 cột/72.250 bản ghi, missing/ID/timestamp, phân bố trường và ứng viên rule. Có bằng chứng failure thực tế; không suy diễn từ Activity. Hợp đồng đã viết để nhóm review, chưa có xác nhận Tuấn. |
| 2 — Loader | Có đường dẫn/upload, kiểm tra cột, encoding, file rỗng/CSV hỏng, báo số đọc/bỏ và định danh theo byte nguồn. Test dữ liệu lỗi và full dataset chạy qua. |
| 3 — Normalizer | Có normalize dùng lại, cờ timestamp lỗi, sort ổn định, raw/khóa bất biến, cột thời gian, bộ chuẩn hóa đầy đủ, mẫu 1.000 dòng và schema. |
| 4 — Rule Engine | Có rule/config/reason, ít nhất ba rule khớp dữ liệu thật, không cần Anomaly. Hiện sáu rule bật tạo 1.301 alert; một rule netcat tắt có lý do. Auth dùng failure rõ và cửa sổ quá khứ. |
| 5 — Kiểm chứng rule | Có gộp source_row_id, rule_ids, metric từng rule, lịch sử thay đổi kỹ thuật, TP/FP và giới hạn. Mẫu 25/rule; auth chỉ có 8 alert nên kiểm tra cả 8, không bịa đủ 20–30. Schema v1.0 đóng băng kỹ thuật, Tuấn chưa ký xác nhận. |
| 6 — Correlation | Có nhóm theo User/Agent, cửa sổ và inactivity gap, timeline, bảng 7.501 nhóm và ví dụ. Test append tương lai giữ membership/group_id cũ, snapshot as_of giữ thống kê lịch sử. Thống kê toàn nhóm vẫn tăng khi có sự kiện mới, không dùng làm feature quá khứ. |
| 7 — Severity | Có mapping/config, bốn mức và test biên; dùng prefix alert/activity và giờ nguồn, không dùng nhãn hoặc ML. Bảng prioritized có mức cuối và severity_reason. |
| 8 — Pipeline | Có Rule → Correlation → Severity, upload/dashboard rule-based và detected_logs 72.250 dòng, join theo source_row_id; có thời gian và biên bản lỗi tích hợp. AppTest thay cho nghiệm thu trực tiếp của Tuấn. |
| 9 — Kiểm thử | Chạy lại toàn suite sau đổi tên: 198 test và 90 subtest pass, 0 fail/error/skip; khoảng 64,45 giây. JUnit riêng ở review_pytest.xml, không ghi đè biên bản lần chốt trước. |

## Các điểm tài liệu sửa trong lần rà soát này

- RULE_ENGINE_LIMITATIONS.md còn ghi chưa có dashboard và chưa chấm ngữ cảnh: đã cập nhật theo Task 7–9.
- ALERT_SCHEMA_V1.md còn mô tả severity merged luôn là mức gốc: đã phân biệt bảng đóng băng Task 5 và bảng prioritized/pipeline.
- INTEGRATION_CONTRACT.md còn nêu predict_logs là API đã có và ML chỉ là khung: đã ghi đúng API hiện có predict trả DataFrame; ML vẫn chưa ghép vào dashboard/severity.

Không sửa rule, ngưỡng, model, CSV gốc hoặc CSV của gói data_for_ml để tăng metric. Log/JUnit/manifest lịch sử giữ nguyên; provenance đường dẫn cũ là vị trí lúc xuất.

## Kết luận và giới hạn nghiệm thu

Phần kỹ thuật rule-based đáp ứng các hạng mục đã triển khai và các kiểm chứng tự động hiện có. Không kết luận toàn bộ sản phẩm đồ án đã hoàn thành hoặc bộ rule phát hiện tốt mọi loại bất thường.

- Tuấn còn cần xác nhận hợp đồng/schema và nghiệm thu trực tiếp luồng giao diện; không ghi là đã có đồng thuận nhóm.
- Union theo nhãn: TP=450, FP=851, FN=41.091, TN=29.858; precision khoảng 34,59%, recall khoảng 1,08%. Đúng logic prototype không đồng nghĩa độ bao phủ tốt. Nhãn tham chiếu cũng không chứng minh tấn công đã xác minh.
- Thiếu User khiến 1.372 event không có group; 216/330 failure thiếu User không tham gia rule đếm theo User. Các event vẫn được giữ.
- Chưa có holdout độc lập cho rule, streaming/late arrival, timezone/lịch vận hành đã xác minh hoặc tích hợp ML vào severity. EDA/training/threshold/drift ML và bộ slide/báo cáo cuối là phần phối hợp nhóm, không được coi là hoàn tất nhờ test rule-based pass.

[review_checks.json](review_checks.json) ghi kiểm tra độc lập checksum, đọc các bảng bàn giao, so full output/raw với nguồn, tính lại metric và đối chiếu hash schema. [review_pytest.xml](review_pytest.xml) ghi kết quả test lần rà soát.
