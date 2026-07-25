# Hướng dẫn sử dụng — Gitea N-day Detection Toolset

## 1. Toolset này là gì

Một tool Python dòng lệnh, nhận vào **1 URL Gitea**, tự động:

1. **Fingerprint** — xác định version Gitea đang chạy.
2. **Xác định applicability** — trong 3 CVE đã biết, CVE nào áp dụng được với version đó.
3. **Analyze** — với mỗi CVE áp dụng được, gửi đúng 1 cặp request (baseline + payload) đã verify trong quá trình reproduce thủ công trước đó, so sánh để xác nhận lỗ hổng có thật sự tồn tại hay không.
4. **Report** — xuất 1 file markdown theo format OWASP WSTG (Ref ID, Risk Level, Evidence, Steps to Reproduce, Remediation).

**Toolset KHÔNG làm:** không tự động khai thác để lấy dữ liệu thật, không leo thang quyền, không brute-force nhiều payload liên tiếp, không phá hoại dữ liệu ngoài phạm vi ephemeral resource cần thiết để test (và tool tự dọn dẹp resource đó ngay sau khi test xong).

## 2. Cảnh báo phạm vi sử dụng

Tool **chỉ được chạy trên môi trường lab do chính bạn dựng** (`localhost`, `127.0.0.1`, `::1`). Nếu URL truyền vào không thuộc whitelist này, tool sẽ **từ chối chạy ngay từ đầu** và in cảnh báo — không gửi bất kỳ request nào khác.

Muốn thêm 1 hostname nội bộ khác (đã được cấp phép rõ ràng, ví dụ 1 domain nội bộ trong VPN công ty), dùng flag `--allow-host <hostname>` (có thể lặp lại nhiều lần).

**Không bao giờ chạy tool này nhắm vào domain/IP bạn không có quyền kiểm thử hợp pháp.**

## 3. Cài đặt

Yêu cầu Python ≥ 3.10.

```bash
pip install -r requirements.txt
```

Chỉ có 2 dependency: `requests`, `beautifulsoup4`.

## 4. Danh sách CVE đã cover

| CVE | Ref ID | Loại lỗi | Version bị ảnh hưởng | Cần đăng nhập? |
|---|---|---|---|---|
| CVE-2022-38183 | VULN-01 | IDOR — leak title issue qua "add issue to project" | Gitea < 1.16.9 | Có |
| CVE-2022-42968 | VULN-02 | Argument Injection qua `?branch=` tại `/graph` | Gitea < 1.17.3 | Không |
| CVE-2024-6886 | VULN-03 | Stored XSS qua Repository Description | Gitea < 1.22.1 | Có |

## 5. Cách chạy

Cú pháp tổng quát:

```bash
python main.py --url <URL Gitea> [flags theo CVE áp dụng được]
```

### Các flag

| Flag | Bắt buộc khi | Ý nghĩa |
|---|---|---|
| `--url` | luôn luôn | Base URL Gitea, ví dụ `http://localhost:3002` |
| `--username`, `--password` | có CVE cần auth (VULN-01, VULN-03) áp dụng được | Tài khoản Gitea bất kỳ (không cần quyền admin) để tool tự động login |
| `--target-issue-id` | VULN-01 áp dụng được | ID (global, không phải số thứ tự trong repo) của 1 issue thuộc repo **private** của người khác — dùng làm mục tiêu test IDOR |
| `--graph-owner`, `--graph-repo` | VULN-02 áp dụng được | Owner/tên của 1 repo **public** có ít nhất vài commit, dùng để test `/graph` |
| `--timeout` | không | Timeout mỗi HTTP request (giây), mặc định 10 |
| `--output` | không | Đường dẫn file report; mặc định tự sinh `reports/gitea_nday_report_<timestamp>.md` |
| `--allow-host` | không | Thêm hostname nội bộ vào whitelist (ngoài localhost mặc định) |

Nếu 1 CVE áp dụng được (theo version) nhưng thiếu flag/creds cần thiết, CVE đó sẽ được ghi nhận **`inconclusive`** trong report — các CVE khác vẫn chạy bình thường, không bị bỏ qua âm thầm.

### Ví dụ thực tế (đã test trên lab)

```bash
# Lab Gitea 1.17.2 — test CVE-2022-42968 (không cần auth)
python main.py --url http://localhost:3002 \
  --graph-owner LeHung --graph-repo repo1

# Lab Gitea 1.16.8 — test CVE-2022-38183 (cần auth + target-issue-id)
python main.py --url http://localhost:3001 \
  --username ndaytester --password 'NdayTest123!' \
  --target-issue-id 1

# Lab Gitea 1.22.0 — test CVE-2024-6886 (cần auth)
python main.py --url http://localhost:3003 \
  --username ndaytester --password 'NdayTest123!'
```

Có thể truyền tất cả flag cùng lúc trong 1 lần chạy — tool tự bỏ qua (not_applicable) những CVE không khớp version.

## 6. Output console (ví dụ thật)

```
[*] Target: http://localhost:3002
[*] Fingerprinted version: 1.17.2

[*] Checking CVE-2022-42968 (VULN-02)...
    -> vulnerable

[*] Checking CVE-2022-38183 (VULN-01)...
    -> not applicable (version 1.17.2 không < (1, 16, 9))

[*] Checking CVE-2024-6886 (VULN-03)...
    -> inconclusive: thiếu --username/--password

[*] Report đã ghi tại: reports/gitea_nday_report_20260722_234804.md
```

## 7. Output report (rút gọn, ví dụ thật từ lab)

```markdown
# Gitea N-day Detection Report

- **Target:** http://localhost:3002
- **Fingerprinted version:** 1.17.2
- **Methodology:** Recon (fingerprint version) + Analyze (gửi 1 request
  payload, so sánh với baseline) theo OWASP WSTG.

## Summary

| Ref ID | CVE | Risk Level | Status |
|---|---|---|---|
| VULN-02 | CVE-2022-42968 | High | 🔴 VULNERABLE |
| VULN-01 | CVE-2022-38183 | - | ⚪ NOT APPLICABLE |
| VULN-03 | CVE-2024-6886 | - | 🟡 INCONCLUSIVE |

### VULN-02: CVE-2022-42968

- **Status:** 🔴 VULNERABLE
- **Risk Level:** High
- **CWE:** CWE-88 — Argument Injection or Modification

**Detail:**

Payload '?branch=-n1&branch=main' làm số commit hiển thị giảm từ 5 xuống 1.
Đây là bằng chứng '-n1' đã được git hiểu như flag giới hạn output, không phải
tên branch.

**Evidence:**
Baseline: 5 commit hiển thị
Payload: 1 commit hiển thị

**Steps to Reproduce:**
curl -i "http://localhost:3002/LeHung/repo1/graph"
curl -i "http://localhost:3002/LeHung/repo1/graph?branch=-n1&branch=main"

**Remediation:**
Nâng cấp Gitea lên >= 1.17.3 ...
```

## 8. Đọc hiểu 4 trạng thái kết quả

| Status | Ý nghĩa |
|---|---|
| 🔴 `vulnerable` | Đã gửi request PoC, quan sát response/HTML thực tế khớp đúng hành vi lỗi mô tả trong CVE |
| 🟢 `not_vulnerable` | Đã gửi request PoC, nhưng hành vi lỗi KHÔNG xảy ra (bản đã patch, hoặc feature liên quan chưa tồn tại ở version đó) |
| 🟡 `inconclusive` | Không đủ điều kiện để kết luận: thiếu credentials/tham số bắt buộc, lỗi mạng/timeout, hoặc cấu trúc response khác với logic parse hiện tại — **không phải nghĩa là "an toàn"** |
| ⚪ `not_applicable` | Version fingerprint được nằm ngoài range bị ảnh hưởng của CVE đó, tool không chạy analyze |

## 9. Báo cáo PoC gốc (tham khảo chi tiết root cause)

3 báo cáo PoC thủ công gốc (đã reproduce tay từng CVE trước khi viết tool) nằm trong thư mục `report/` của repo:

- `Report_VULN-01_CVE-2022-38183.md`
- `Report_VULN-02_CVE-2022-42968.md`
- `Report_VULN-03_CVE-2024-6886.md`

## 10. Lưu ý khi test

- Mỗi lần chạy VULN-01/VULN-03, tool **tự tạo và tự xoá** 1 repo (và project với VULN-01) tạm thời dưới account bạn cung cấp — không cần dọn dẹp thủ công.
- Với VULN-01, `--target-issue-id` phải là ID issue **thật sự tồn tại và thuộc repo mà account test không có quyền đọc** — nếu không, tool sẽ trả `inconclusive` (không tìm thấy issue trên board sau khi POST) thay vì `vulnerable`/`not_vulnerable` sai.
