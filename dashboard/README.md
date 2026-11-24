# Streamlit dashboard

Hướng dẫn cài đặt và chạy thống nhất tại [README gốc](../README.md).

Entry point: `dashboard/app.py`. `service.py` gọi loader → normalize → pipeline rule-based; `views.py` hiển thị Overview, Events, Alerts, Timeline và trạng thái ML.

Dashboard hiện chưa gọi ML inference. Hợp đồng đầu vào/đầu ra ở [PIPELINE_API.md](../docs/PIPELINE_API.md); phạm vi bàn giao và phối hợp với Tuấn ở [THO_HANDOFF.md](../docs/THO_HANDOFF.md).
