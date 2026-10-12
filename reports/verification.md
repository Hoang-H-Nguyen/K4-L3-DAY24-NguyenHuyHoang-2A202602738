# Verification — điền trước khi nộp

## CP3a — PII gate

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `2 passed`; `gold=118`, `pred=118`, `tp=118`.
- Precision: `1.000`; recall: `1.000`.
- Giới hạn: detector dựa trên regex và ngữ cảnh nhãn (`CCCD`, `STK`/`số tài khoản`), nên có thể bỏ sót giá trị viết bằng chữ, bị che ký tự bất thường, hoặc số tài khoản không có nhãn; regex email cũng không thay thế bộ phân tích đầy đủ theo mọi trường hợp RFC.

## CP3b/CP3c — Policy và OBO

- `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`: `4 passed`.
- `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp`: `5 passed`.
- Hai chiều đã được kiểm: `support_l1` bị deny khi đọc customer restricted; `dpo` được allow với purpose hợp lệ; quyền agent con không vượt `parent_scopes`.

## CP3d/CP3e — Split, injection và ledger

- `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp`: `1 passed`; khách `KH-000777` chỉ xuất hiện trong text không bị đọc, trong khi khách gắn với ticket hợp lệ vẫn được đọc.
- `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp`: `8 passed`, không có `SKIP` (4 lure × 2 principal).
- `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp`: `3 passed`, gồm kiểm tra phát hiện sửa dòng và bắt buộc `reason`.
- CLI evidence: `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` tạo `reports/ledger.jsonl`; `verify(...)` trả `True`.
- Ledger có dòng `tool=http_post`, `decision=deny`, `on_behalf_of=dpo`, lý do `restricted data cannot be used in an egress-enabled run`. Ledger chỉ lưu `args_hash`, không lưu hồ sơ/PII trong arguments.

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:
