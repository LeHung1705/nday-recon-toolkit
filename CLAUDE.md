# CLAUDE.md — Gitea N-day Detection Toolset

## Mục đích

Tool recon + analyze (KHÔNG exploit) cho 3 CVE đã reproduce thành công trên
Gitea, dùng làm artifact Phase 2+3 của chương trình intern security tại ECQ.
Input: 1 URL Gitea. Output: report markdown format WSTG xác nhận từng CVE có
tồn tại hay không trên target đó.

3 CVE trong scope (báo cáo PoC gốc ở `report/`):

| CVE | Ref ID | Loại lỗi | Version bị ảnh hưởng | Module |
|---|---|---|---|---|
| CVE-2022-38183 | VULN-01 | IDOR — leak issue title qua "add issue to project" | < 1.16.9 | `checks/cve_2022_38183.py` |
| CVE-2022-42968 | VULN-02 | Argument Injection qua `?branch=` tại `/graph` | < 1.17.3 | `checks/cve_2022_42968.py` |
| CVE-2024-6886 | VULN-03 | Stored XSS qua Repository Description | < 1.22.1 | `checks/cve_2024_6886.py` |

## Nguyên tắc bắt buộc (KHÔNG được vi phạm khi sửa/mở rộng code)

1. **Chỉ recon + analyze.** Mỗi module CVE chỉ gửi số request tối thiểu cần
   thiết để XÁC NHẬN lỗ hổng tồn tại (so baseline vs payload) — không brute-force
   nhiều payload liên tiếp, không tự động khai thác để lấy dữ liệu thật ngoài
   mục đích chứng minh khái niệm, không tự động escalate quyền.
2. **Chỉ chạy trên target đã whitelist.** `core/guard.py::validate_target()`
   PHẢI được gọi trước bất kỳ request nào khác trong `main.py`. Mặc định chỉ
   cho phép `localhost`/`127.0.0.1`/`::1`/`0.0.0.0`; thêm host khác chỉ qua
   flag `--allow-host` do người dùng chủ động khai báo. Không bao giờ nới lỏng
   whitelist này trong code mặc định.
3. **Không phá hoại dữ liệu.** Module nào tạo ephemeral resource (repo/project
   test) để phục vụ analyze thì PHẢI tự xoá lại (`finally` block) sau khi xong,
   kể cả khi phát hiện vulnerable hay khi có exception giữa chừng.
4. **Không silent-fail nguy hiểm.** Lỗi mạng/timeout/parse trong 1 module chỉ
   được làm module đó trả `Status.INCONCLUSIVE`, không được để exception làm
   crash toàn bộ `main.py` (các CVE khác vẫn phải chạy tiếp).

## Cấu trúc thư mục

```
main.py                  # CLI orchestrator: guard -> fingerprint -> loop checks -> report
core/
  guard.py               # whitelist target, raise TargetNotAllowedError nếu vi phạm
  http_client.py          # GiteaSession: wraps requests.Session, tự động login CSRF flow
  fingerprint.py          # GET /api/v1/version -> version string
  version_compare.py       # parse "X.Y.Z..." -> tuple, so sánh applicability
  models.py                # Status enum, CheckResult dataclass
  reporter.py               # render report markdown format WSTG
checks/
  registry.py               # ALL_CHECKS: danh sách CheckEntry (cve_id, module, affected_below, requires_auth, required_args)
  cve_2022_38183.py          # mỗi file = 1 CVE, export analyze(ctx) -> CheckResult
  cve_2022_42968.py
  cve_2024_6886.py
report/                       # báo cáo PoC gốc (manual), tham chiếu evidence/root cause
reports/                      # output report tự sinh của tool (gitignore nếu cần)
```

## Quy ước thêm 1 CVE module mới (vd MinIO/Portainer sau này)

1. Tạo file mới trong `checks/`, vd `checks/cve_xxxx_yyyy.py`.
2. Export đúng 1 hàm: `def analyze(ctx: CheckContext) -> CheckResult`.
   - `ctx.base_url`, `ctx.timeout`, `ctx.args` (argparse.Namespace), `ctx.session`
     (`core.http_client.GiteaSession`, đã login sẵn nếu `requires_auth=True`).
   - Trả về `CheckResult` (từ `core.models`) với `status` là 1 trong 4 giá trị
     của `Status` — không tự ý thêm status mới.
   - Nếu module tạo ephemeral resource, dùng `try/finally` để đảm bảo xoá lại.
3. Đăng ký 1 `CheckEntry` mới trong `checks/registry.py::ALL_CHECKS` — điền
   đúng `affected_below` (version tuple), `requires_auth`, `required_args`
   (list tên attribute trên `argparse.Namespace` mà module cần).
4. Nếu module cần thêm CLI flag riêng, thêm vào `parse_args()` trong `main.py`
   — **không sửa logic loop chính**, chỉ thêm flag.
5. Không hardcode logic CVE cụ thể nào trong `main.py`/`core/` — mọi thứ đặc
   thù CVE nằm trong file module tương ứng.

## Cách chạy test cho từng module

Chạy trực tiếp qua `main.py` nhắm vào lab Docker tương ứng (xem `report/` để
biết version/port đã dùng khi reproduce):

```bash
# CVE-2022-42968 — không cần auth
python main.py --url http://localhost:3002 --graph-owner LeHung --graph-repo repo1

# CVE-2022-38183 — cần auth + target-issue-id (issue private của user khác)
python main.py --url http://localhost:3001 --username userb --password <pw> --target-issue-id 1

# CVE-2024-6886 — cần auth, tự tạo/xoá ephemeral repo
python main.py --url http://localhost:3003 --username LeHung --password <pw>
```

Report markdown ghi ra `reports/gitea_nday_report_<timestamp>.md`. Kiểm tra
`status` của từng finding khớp kỳ vọng (vulnerable trên bản lỗi, not_vulnerable
trên bản đã patch) trước khi coi module đã hoàn thành.

## Không làm (out of scope, không tự ý thêm)

- Docker packaging / CI (Phase 3 sau, chưa cần trong bước này).
- Brute-force `--target-issue-id` theo range để tự dò issue private.
- Bất kỳ payload `git log` khác ngoài `-n1`/`-1` đã verify trong `report/VULN-02`
  (report gốc ghi rõ chưa test các flag nguy hiểm hơn như `--output=`).
- Test trên domain/IP ngoài whitelist — kể cả khi "chỉ để thử".
