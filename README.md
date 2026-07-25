# nday-recon-toolkit

Tool recon + analyze (KHÔNG exploit) cho các lỗ hổng N-day đã biết trên Gitea.
Nhập vào **1 URL Gitea**, tool tự động:

1. Fingerprint version đang chạy (`GET /api/v1/version`).
2. Đối chiếu version đó với danh sách CVE đã biết, xác định CVE nào áp dụng được.
3. Với mỗi CVE áp dụng được, tự gửi request cần thiết (baseline vs payload) để
   xác nhận lỗ hổng có thực sự tồn tại trên target hay không — không phụ
   thuộc vào số hiệu version công bố, mà verify bằng hành vi thực tế.
4. Xuất 1 report markdown duy nhất theo format OWASP WSTG (Ref ID, Risk
   Level, Evidence, Steps to Reproduce, Remediation), gộp cả CVE không áp
   dụng được / thiếu điều kiện test.

Đây là artifact Phase 2+3 của chương trình intern security tại ECQ — mục
tiêu là biến quy trình reproduce PoC thủ công (đã làm ở Phase 1, xem
`report/`) thành 1 tool tái sử dụng được cho các lần audit sau.

## CVE đã cover

| CVE | Loại lỗi | Version bị ảnh hưởng | Report PoC gốc (Phase 1) |
|---|---|---|---|
| CVE-2022-38183 | IDOR — leak issue title qua "add issue to project" | Gitea < 1.16.9 | [report/Report_VULN-01_CVE-2022-38183.md](report/Report_VULN-01_CVE-2022-38183.md) |
| CVE-2022-42968 | Argument Injection qua `?branch=` tại `/graph` | Gitea < 1.17.3 | [report/Report_VULN-02_CVE-2022-42968.md](report/Report_VULN-02_CVE-2022-42968.md) |
| CVE-2024-6886 | Stored XSS qua Repository Description | Gitea < 1.22.1 | [report/Report_VULN-03_CVE-2024-6886.md](report/Report_VULN-03_CVE-2024-6886.md) |

## Nguyên tắc thiết kế (không thương lượng khi mở rộng)

- **Chỉ recon + analyze, không exploit thật.** Mỗi module chỉ gửi số request
  tối thiểu để xác nhận lỗ hổng tồn tại, không brute-force nhiều payload,
  không tự động khai thác lấy dữ liệu thật, không tự leo thang quyền.
- **Chỉ chạy trên target đã whitelist.** Mặc định chỉ cho phép
  `localhost`/`127.0.0.1`/`::1`/`0.0.0.0`. Muốn thêm host nội bộ khác phải
  khai báo tường minh qua `--allow-host`, không bao giờ nới whitelist ngầm.
- **Không phá hoại dữ liệu.** Module nào tạo resource tạm (repo/project test)
  để phục vụ verify thì tự xoá lại ngay sau khi xong — kể cả khi phát hiện
  vulnerable hay có exception giữa chừng.
- **Không silent-fail nguy hiểm.** Lỗi mạng/timeout/parse ở 1 CVE chỉ làm
  CVE đó thành `inconclusive`, không làm sập toàn bộ lần chạy — các CVE khác
  vẫn tiếp tục.

⚠️ **Chỉ dùng trên môi trường bạn có quyền kiểm thử hợp pháp** (lab tự dựng,
hoặc hệ thống nội bộ đã được cấp phép rõ ràng qua `--allow-host`). Không
target vào bất kỳ domain/IP nào bạn không sở hữu hoặc chưa được uỷ quyền.

## Kiến trúc (tóm tắt)

```
main.py            CLI orchestrator: guard -> fingerprint -> loop qua từng CVE -> report
core/               hạ tầng dùng chung, KHÔNG chứa logic riêng của CVE nào
  guard.py           chặn target ngoài whitelist
  http_client.py      session HTTP, tự login + xử lý CSRF
  fingerprint.py      lấy version qua API
  version_compare.py  so sánh version
  models.py            Status enum + CheckResult
  reporter.py           render report markdown WSTG
checks/              logic riêng từng CVE, 1 file = 1 CVE, export analyze(ctx)
  registry.py          danh sách CheckEntry: version áp dụng, cần auth không, cần arg gì
  cve_2022_38183.py
  cve_2022_42968.py
  cve_2024_6886.py
```

`core/` không biết gì về CVE cụ thể — mọi thứ đặc thù nằm trong `checks/`.
Muốn thêm 1 CVE mới, xem hướng dẫn trong [CLAUDE.md](CLAUDE.md) — chỉ cần
thêm 1 file trong `checks/` + 1 dòng đăng ký trong `registry.py`, không đụng
`main.py`.

## Cài đặt

Yêu cầu Python ≥ 3.10.

```bash
pip install -r requirements.txt
```

(`requests`, `beautifulsoup4`)

## Cách dùng

```bash
python main.py --url http://localhost:3002 \
  --graph-owner LeHung --graph-repo repo1 \
  --username LeHung --password '<mật khẩu account test>' \
  --target-issue-id 1
```

**1 lệnh duy nhất tự động check cả 3 CVE** trên target đó — CVE nào không áp
dụng (version không thoả) hoặc thiếu tham số cần thiết sẽ được báo rõ lý do
trong report thay vì bị bỏ qua âm thầm.

| Flag | Bắt buộc khi | Ý nghĩa |
|---|---|---|
| `--url` | luôn | Base URL Gitea, vd `http://localhost:3002` |
| `--username`, `--password` | CVE-2022-38183, CVE-2024-6886 áp dụng được | Account dùng để auto-login |
| `--target-issue-id` | CVE-2022-38183 áp dụng được | ID issue thuộc repo private của người khác — dùng để chứng minh IDOR (tool không tự dò/brute-force ID này) |
| `--graph-owner`, `--graph-repo` | CVE-2022-42968 áp dụng được | 1 repo public (≥2 commit) dùng để test `/graph` |
| `--timeout` | không | HTTP timeout, mặc định 10s |
| `--output` | không | Đường dẫn file report, mặc định `reports/gitea_nday_report_<timestamp>.md` |
| `--allow-host` | không | Thêm hostname nội bộ vào whitelist (có thể lặp lại) |

### Ví dụ output console

```
[*] Target: http://localhost:3002
[*] Fingerprinted version: 1.17.2

[*] Checking CVE-2022-42968 (VULN-02)...
    -> vulnerable
[*] Checking CVE-2022-38183 (VULN-01)...
    -> not applicable (version 1.17.2 không < (1, 16, 9))
[*] Checking CVE-2024-6886 (VULN-03)...
    -> inconclusive: thiếu --username/--password

[*] Report đã ghi tại: reports/gitea_nday_report_20260722_190000.md
```

### Trích report markdown

```markdown
## Summary

| Ref ID | CVE | Risk Level | Status |
|---|---|---|---|
| VULN-02 | CVE-2022-42968 | High | 🔴 VULNERABLE |
| VULN-01 | CVE-2022-38183 | - | ⚪ NOT APPLICABLE |
| VULN-03 | CVE-2024-6886 | - | 🟡 INCONCLUSIVE |

### VULN-02: CVE-2022-42968
...
```

## Kết quả verify trên 3 lab Docker (đúng version từng CVE)

| Lab | Version | Kết quả |
|---|---|---|
| `localhost:3001` | 1.16.8 | VULN-01 (IDOR) → 🔴 vulnerable |
| `localhost:3002` | 1.17.2 | VULN-02 (Arg Injection) → 🔴 vulnerable |
| `localhost:3003` | 1.22.0 | VULN-03 (Stored XSS) → 🔴 vulnerable |

Chi tiết quá trình dựng lab, các vấn đề thực tế gặp phải khi test đa version
(CSRF nhúng khác cách, API bỏ cookie-auth ở bản mới, layout HTML khác nhau)
và cách xử lý: xem [docs_giai_thich_kien_truc.md](docs_giai_thich_kien_truc.md).

## Tài liệu liên quan

- [CLAUDE.md](CLAUDE.md) — quy ước bắt buộc khi sửa/mở rộng code
- [docs_huong_dan_su_dung.md](docs_huong_dan_su_dung.md) — hướng dẫn sử dụng chi tiết
- [docs_giai_thich_kien_truc.md](docs_giai_thich_kien_truc.md) — giải thích kiến trúc & bài học thực tế khi build
- [report/](report/) — 3 báo cáo PoC gốc (Phase 1, làm thủ công trước khi có tool)

## Không làm (out of scope)

- Docker packaging / CI (dự kiến Phase sau).
- Brute-force `--target-issue-id` theo range để tự dò issue private.
- Payload `git log` nào khác ngoài `-n1`/`-1` đã verify (chưa test các flag
  nguy hiểm hơn như `--output=`).
- Test trên domain/IP ngoài whitelist, kể cả "chỉ để thử".
