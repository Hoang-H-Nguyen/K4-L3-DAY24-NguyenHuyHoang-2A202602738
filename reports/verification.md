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

## CP4 — Supply chain

- Môi trường: Linux `7.0.0-38-generic` x86_64; Python `3.13.11`; pytest `9.1.1`; Gitleaks `8.30.1`; pip-tools `7.6.2`; pre-commit `4.6.2`.
- `gitleaks git --config .gitleaks.toml --redact .`: exit `1`, quét 8 commit và tìm đúng 1 token synthetic ở commit `1bdd849`, rule `lab24-synthetic-token` (kết quả mong đợi).
- `gitleaks dir --config .gitleaks.toml --redact .`: exit `0`, không finding; không cần allowlist `.venv`.
- `pip-compile --generate-hashes --output-file=requirements.lock requirements.txt`: thành công; `python -m pip install --require-hashes -r requirements.lock`: thành công.
- `pre-commit install`: đã cài hook; `pre-commit run --all-files`: `Detect hardcoded secrets ... Passed`.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`: `3 passed` sau khi hoàn thiện incident note.

## CP5 — Replay sau containment

- Sau khi dừng/reset sink, `python -m pytest tests/ -q --basetemp=.pytest_tmp`: `33 passed`, `0 failed`, `0 skipped` trong `0.56s`.
- Sau pytest đã reset/bật lại sink, chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`, rồi chép riêng `sink.log` thành `attack-after.log` và tắt sink.
- Đối chiếu: `reports/attack-before.log` có 4 dòng POST chứa hồ sơ synthetic `KH-000999`; `reports/attack-after.log` có 0 dòng và `0` byte.
- Ledger: `reports/ledger.jsonl` có 115 dòng tại thời điểm kiểm, gồm 110 allow và 5 deny. Có 5 dòng `http_post`, tất cả đều deny; dòng mới nhất có reason `restricted data cannot be used in an egress-enabled run` và `on_behalf_of=dpo`.
- `verify(Path('reports/ledger.jsonl'))` trả `True`.

## Lỗi đã gặp và cách xử lý

- Ban đầu thiếu `piptools` và `pre-commit`; đã cài `pip-tools 7.6.2` và `pre-commit 4.6.2`. Lần gọi `python -m piptools compile` không tạo lock trong môi trường này; chạy entrypoint `pip-compile` đã tạo `requirements.lock` thành công rồi kiểm lại bằng `--require-hashes`.
- Lần đầu chạy `tests/test_supply_chain.py` có `1 failed` vì `reports/secrets-incident.md` còn là template; sau khi ghi finding redacted, commit/rule và quy trình rotate, chạy lại đạt `3 passed`.
- Sandbox từng chặn socket localhost khi test fixture tạo sink; chạy test được cấp quyền localhost hoàn tất bình thường. Không có lỗi chức năng còn lại đã biết trong phạm vi test của lab.
