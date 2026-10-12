# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1`, cấu hình `.gitleaks.toml`; mọi lần quét dùng `--redact` để không in giá trị token.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`), file lịch sử `lab-fake-secret.txt`, dòng 1, rule `lab24-synthetic-token`. Đây là credential synthetic và cố ý vô hiệu của bài lab, không được tìm hoặc sử dụng secret thật.
- **Quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact .` quét 8 commit, tìm 1 finding và trả exit code `1`; đây là kết quả mong đợi cho bài tập.
- **Quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` quét working tree, không có finding và trả exit code `0`. Không có false positive trong `.venv`, vì vậy không sửa allowlist.
- **Nếu là credential thật:** phải thu hồi hoặc rotate tại chính dịch vụ phát hành ngay lập tức, rà log để xác định việc sử dụng trái phép, thay credential ở các hệ thống phụ thuộc, rồi xử lý các bản sao trong Git, cache, artifact, CI log và fork theo quy trình ứng phó sự cố. Chỉ xóa chuỗi khỏi repository không thay thế việc thu hồi phía nhà cung cấp.
- **Vì sao xóa khỏi HEAD hoặc pin dependency chưa đủ:** Git vẫn giữ token trong commit cũ và các clone/fork có thể vẫn chứa bản sao; pin dependency chỉ kiểm soát phiên bản/mã gói, không vô hiệu hóa credential đã lộ. Nếu cần viết lại lịch sử thì vẫn phải phối hợp với mọi bản sao, nhưng rotate/thu hồi là hành động ưu tiên.
