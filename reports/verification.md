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

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:
