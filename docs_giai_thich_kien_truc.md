# Gitea N-day Detection Toolset — Đã làm gì & Giải thích kiến trúc

## 1. Bối cảnh & mục tiêu

Trước khi có tool này, 3 lỗ hổng (CVE-2022-38183, CVE-2022-42968, CVE-2024-6886)
đã được reproduce **thủ công** trên 3 lab Docker Gitea riêng biệt (version
1.16.8 / 1.17.2 / 1.22.0), mỗi lỗi có 1 báo cáo PoC chi tiết trong `report/`.

Mục tiêu của bước này (Phase 2+3 chương trình intern): biến quy trình thủ
công đó (dùng Burp Suite, curl tay, đọc HTML bằng mắt) thành **1 tool Python
tái sử dụng được** — nhập 1 URL, tool tự làm lại đúng các bước đã verify tay,
và tự kết luận + xuất report chuẩn WSTG.

Nguyên tắc xuyên suốt: tool chỉ **recon (fingerprint) + analyze (so baseline
vs payload)**, không tự động khai thác/leo thang, và **không bao giờ chạy vào
target ngoài localhost/lab đã whitelist**.

## 2. Cấu trúc thư mục và vai trò từng phần

```
main.py                  <- điểm vào CLI, điều phối toàn bộ luồng
core/                    <- hạ tầng dùng chung, KHÔNG chứa logic riêng của CVE nào
  guard.py               <- chặn target ngoài whitelist
  http_client.py         <- quản lý session HTTP + login + CSRF
  fingerprint.py         <- gọi API lấy version Gitea
  version_compare.py     <- so sánh version dạng "1.16.8+dev..." 
  models.py              <- định nghĩa "CheckResult" — format kết quả chung
  reporter.py            <- render kết quả thành file markdown WSTG
checks/                  <- logic riêng của từng CVE, 1 file = 1 CVE
  registry.py            <- "danh bạ" — khai báo CVE nào, applicable khi nào, cần gì
  cve_2022_38183.py       <- IDOR
  cve_2022_42968.py       <- Argument Injection
  cve_2024_6886.py        <- Stored XSS
report/                  <- 3 báo cáo PoC gốc (viết tay, làm trước khi có tool)
reports/                 <- report tool tự sinh ra mỗi lần chạy
```

**Nguyên tắc phân chia:** `core/` không được biết gì về CVE cụ thể (không có
if/else theo cve_id) — mọi thứ đặc thù nằm trong `checks/`. Nhờ vậy thêm 1 CVE
mới (ví dụ sau này làm thêm MinIO/Portainer) chỉ cần thêm 1 file trong
`checks/` + 1 dòng trong `registry.py`, không đụng vào `main.py` hay `core/`.

## 3. Luồng chạy (`main.py`)

```
1. Parse CLI args (--url, --username, --password, --target-issue-id, ...)
        │
2. core/guard.py::validate_target(url)
        │   -> hostname không phải localhost/127.0.0.1/::1/whitelist?
        │      => in cảnh báo, exit ngay, KHÔNG gửi request nào khác
        ▼
3. core/fingerprint.py::get_version(url)
        │   -> GET /api/v1/version -> "1.17.2" -> parse thành tuple (1,17,2)
        │   -> lỗi mạng/parse => dừng toàn bộ chương trình (không an toàn nếu
        │      không biết version mà vẫn chạy analyze)
        ▼
4. Với mỗi CVE trong checks/registry.py::ALL_CHECKS (lặp tuần tự):
        │
        ├─ version có nằm trong range bị ảnh hưởng không?
        │     Không -> ghi nhận "not_applicable", sang CVE tiếp theo
        │
        ├─ CVE này có cần login không? Có login rồi chưa?
        │     Cần mà thiếu --username/--password -> "inconclusive", sang tiếp
        │     Cần mà có creds -> gọi core/http_client.py::login() 1 lần,
        │       dùng lại session này cho các CVE cần auth khác
        │
        ├─ CVE này có thiếu tham số riêng không (vd --target-issue-id)?
        │     Thiếu -> "inconclusive", sang tiếp
        │
        └─ Đủ điều kiện -> import module trong checks/, gọi analyze(ctx)
              -> bọc trong try/except: lỗi bất ngờ nào cũng chỉ làm CVE này
                 thành "inconclusive", KHÔNG làm sập cả chương trình
        ▼
5. core/reporter.py::write_report(...) -> ghi file markdown, in đường dẫn ra console
```

## 4. Giải thích từng file trong `core/`

### `guard.py`
Hàm `validate_target()` chỉ làm 1 việc: parse hostname từ URL, so với tập
`{localhost, 127.0.0.1, ::1, 0.0.0.0}` (+ hostname thêm qua `--allow-host`).
Không khớp thì raise exception, `main.py` bắt được thì dừng ngay — đây là lớp
bảo vệ đầu tiên, chạy **trước cả fingerprint**, để đảm bảo dù code phía sau có
bug gì cũng không lỡ gửi request ra ngoài lab.

### `http_client.py` — phần phức tạp nhất, có nhiều bài học thực tế
`GiteaSession` bọc quanh `requests.Session`, xử lý 2 việc:

1. **Login tự động** (`login(username, password)`):
   GET trang `/user/login` để lấy CSRF token nhúng trong HTML, rồi POST
   credentials kèm token đó. Xác nhận thành công bằng cách kiểm tra cookie
   `i_like_gitea` xuất hiện sau khi POST (đây là cookie riêng của Gitea, tín
   hiệu đáng tin hơn là chỉ nhìn status code).

2. **Lấy CSRF token cho các form POST khác** (tạo project, gán issue...).
   → Đây là chỗ phát sinh vấn đề thực tế khi test trên 2 bản Gitea khác nhau:
   Gitea **1.16.8** nhúng CSRF dưới dạng `<input name="_csrf" value="...">`
   trên mọi trang có form. Gitea **1.22.0** đổi cách nhúng: trang không có
   form (ví dụ trang chủ sau khi login) **không còn** thẻ `<input>` đó nữa,
   chỉ còn biến JavaScript `csrfToken: '...'` trong thẻ `<script>`. Code ban
   đầu chỉ tìm `<input>`/`<meta>` nên bị lỗi trên bản 1.22 — đã sửa
   `_extract_csrf()` để thử thêm 1 regex bắt biến JS này làm fallback cuối
   cùng.

3. **Gọi REST API** (`api_json()`) — dùng để tạo/xoá repo ephemeral. Ban đầu
   thử dùng cookie session + header `X-Csrf-Token` (cách này **chạy được trên
   Gitea 1.16.8**), nhưng khi test trên Gitea 1.22.0 thì API trả thẳng
   `401 {"message":"token is required"}` — bản mới đã **bỏ hẳn việc chấp nhận
   cookie session cho API**, chỉ còn nhận API token hoặc HTTP Basic Auth.
   → Giải pháp cuối cùng: `api_json()` dùng **HTTP Basic Auth**
   (username/password đã login) thay vì cookie+CSRF — cách này chạy ổn định
   trên cả 2 bản Gitea, không cần biết bản nào dùng cơ chế API-auth nào.

Đây là ví dụ điển hình của việc **"code lý thuyết chạy được, nhưng thực tế
trên các version khác nhau lại lệch"** — chỉ phát hiện được khi chạy thật
trên cả 3 lab, không thể lường trước hết chỉ bằng đọc source.

### `fingerprint.py`
Chỉ 1 việc: GET `/api/v1/version`, parse JSON, trả về chuỗi version thô +
tuple đã parse. Đây là endpoint không cần auth và có ở mọi bản Gitea hiện đại
nên là cách fingerprint an toàn, không cần đoán qua banner HTML.

### `version_compare.py`
Gitea trả version dạng `"1.16.8+dev-123-abcdef"` — hàm `parse_version()` cắt
lấy 3 số đầu bằng regex, trả tuple `(1, 16, 8)` để so sánh trực tiếp bằng toán
tử `<` của Python (tuple so sánh theo thứ tự phần tử, đúng ngữ nghĩa semver
major.minor.patch).

### `models.py`
Định nghĩa 2 kiểu dữ liệu dùng chung toàn bộ tool:
- `Status` (enum): `vulnerable` / `not_vulnerable` / `inconclusive` /
  `not_applicable` — cố tình giới hạn chỉ 4 giá trị này để tránh mỗi module
  tự bịa ra 1 kiểu status khác nhau.
- `CheckResult` (dataclass): gói toàn bộ thông tin 1 CVE cần để lên report
  (risk level, evidence, request đã gửi, remediation, references...).

### `reporter.py`
Nhận danh sách `CheckResult`, render thành markdown: 1 bảng tóm tắt (summary
table) ở đầu + 1 block chi tiết cho từng CVE theo đúng format WSTG (Ref ID,
Risk Level, Evidence, Steps to Reproduce, Remediation, References).

## 5. Giải thích `checks/registry.py`

Đây là "danh bạ" trung tâm — 1 danh sách `CheckEntry`, mỗi entry gồm:
- `cve_id`, `ref_id`: định danh
- `module_name`: tên module Python sẽ được `import` động (vd
  `"checks.cve_2022_42968"`)
- `affected_below`: version tuple — dưới ngưỡng này thì coi là applicable
- `requires_auth`: CVE này có cần login không
- `required_args`: tên các flag CLI bắt buộc phải có giá trị

`main.py` chỉ lặp qua danh sách này và gọi generic — không có dòng code nào
trong `main.py` biết cụ thể "CVE-2022-38183 là gì". Đây là lý do thêm CVE mới
không cần sửa `main.py`.

## 6. Giải thích từng module trong `checks/`

### `cve_2022_42968.py` — Argument Injection (không cần auth, code trước tiên vì đơn giản nhất)
- Lấy `default_branch` của repo qua API (để ghép cùng payload — nếu chỉ gửi
  `-n1` một mình, Gitea fallback bỏ qua và không thấy tác dụng gì, phải kèm
  1 branch hợp lệ đứng sau như báo cáo gốc đã phát hiện).
- Gửi 2 request: baseline (`/graph` không tham số) và payload
  (`/graph?branch=-n1&branch=<default_branch>`), đếm số commit hiển thị ở mỗi
  response (đếm số link `<a href="/owner/repo/commit/...">` duy nhất).
- Payload làm giảm số commit hiển thị → bằng chứng `-n1` đã được `git log`
  hiểu như flag giới hạn output, không phải tên branch → `vulnerable`.

### `cve_2022_38183.py` — IDOR "add issue to project"
- Tạo 1 repo private + 1 project (Kanban "Basic") **tạm thời** dưới chính
  account của người test — vì Gitea 1.16.8 chưa có REST API cho Project, phải
  dùng đúng web form (`POST /{owner}/{repo}/projects/new`) như báo cáo gốc.
- Gửi đúng 1 request PoC: `POST /{owner}/{repo}/issues/projects` với
  `issue_ids=<target_issue_id>` (issue thuộc repo private của người khác) +
  `id=<project_id vừa tạo>`.
- Không chỉ tin response `{"ok":true}` — GET lại trang board và tìm xem title
  của issue đó có **thực sự xuất hiện** trên board hay không (tránh false
  positive nếu response luôn trả ok:true bất kể thành công thật hay không).
- Dọn dẹp: xoá repo ephemeral (kéo theo project) trong khối `finally`, chạy dù
  kết quả là gì hay có exception giữa chừng.

### `cve_2024_6886.py` — Stored XSS qua Description
- Tạo 1 repo **public** ephemeral với Description chứa đúng payload gốc
  (`<a href="javascript:alert(1)">check</a>`).
- GET `/explore/repos` (không cần login — đúng thực tế: nạn nhân xem trang
  public), tìm đúng card của repo vừa tạo, kiểm tra thẻ `<a>` có còn nguyên vẹn
  hay đã bị lọc/escape.
- **Bài học thực tế khi test:** cấu trúc HTML của trang `/explore/repos` khác
  nhau giữa 2 bản Gitea — bản 1.22.0 dùng class `flex-item`/`flex-item-body`,
  bản 1.16.8 dùng class `item`/`description`. Code ban đầu chỉ hỗ trợ layout
  mới nên khi chạy trên bản 1.16.8, nó "tìm không thấy" description container
  và mặc định trả `not_vulnerable` — **sai lý do** (trông giống đã patch,
  nhưng thực ra là do parser không nhận diện được cấu trúc). Đã sửa lại để hỗ
  trợ cả 2 layout, và quan trọng hơn: khi thực sự không xác định được cấu trúc
  HTML, trả về `inconclusive` thay vì mặc định `not_vulnerable` — nguyên tắc
  "không chắc thì nói không chắc", tránh false negative nguy hiểm hơn false
  positive trong ngữ cảnh báo cáo bảo mật.
- Dọn dẹp: xoá repo ephemeral trong `finally`, giống module IDOR.

## 7. Kết quả test thực tế trên 3 lab Docker

| Lab (port) | Version | VULN-01 (IDOR) | VULN-02 (Arg Injection) | VULN-03 (Stored XSS) |
|---|---|---|---|---|
| 3001 | 1.16.8 | 🔴 vulnerable | not tested (thiếu graph args) | 🟢 not_vulnerable (feature Description-HTML chưa tồn tại ở bản này) |
| 3002 | 1.17.2 | not applicable | 🔴 vulnerable | not tested (thiếu creds) |
| 3003 | 1.22.0 | not applicable | not applicable | 🔴 vulnerable |

Cả 3 kết quả `vulnerable` đều khớp chính xác với PoC thủ công đã ghi trong
`report/`. Mỗi lần chạy, ephemeral repo/project test đều được xác nhận xoá
sạch (kiểm tra lại bằng HTTP 404 sau khi tool chạy xong).

## 8. Những vấn đề thực tế đã gặp và cách xử lý (tóm tắt)

1. **Console Windows không encode được tiếng Việt có dấu** khi in help text —
   fix bằng cách ép `sys.stdout`/`sys.stderr` sang UTF-8 ở đầu `main.py`.
2. **CSRF token nhúng khác cách giữa Gitea 1.16.8 và 1.22.0** — fix bằng cách
   thêm nhiều chiến lược extract token (input tag → meta tag → JS var) trong
   `http_client.py`.
3. **API Gitea 1.22.0 không còn chấp nhận cookie session** (khác 1.16.8) —
   fix bằng cách chuyển toàn bộ gọi API sang HTTP Basic Auth, hoạt động ổn
   định trên cả 2 bản.
4. **Layout HTML trang Explore khác nhau giữa các version** — fix bằng cách
   hỗ trợ song song 2 layout, và bắt buộc trả `inconclusive` khi không nhận
   diện được cấu trúc, thay vì đoán mò `not_vulnerable`.

Tất cả 4 vấn đề trên chỉ phát hiện được nhờ **chạy thật trên cả 3 lab Docker**
sau khi code xong từng module — không thể lường trước hết chỉ bằng đọc report
PoC gốc hoặc đọc source code Gitea.
