"""Đăng ký các CVE check khả dụng.

Thêm 1 CVE mới = thêm 1 CheckEntry vào ALL_CHECKS, KHÔNG cần sửa main.py.
Mỗi module trong checks/ phải export 1 hàm `analyze(ctx: CheckContext) -> CheckResult`.
"""
from dataclasses import dataclass
from typing import Callable

from core.models import CheckResult


@dataclass
class CheckContext:
    """Context truyền vào analyze() của từng module — gom mọi input cần thiết."""

    base_url: str
    timeout: int
    args: object  # argparse.Namespace — module tự đọc field nó cần (vd args.target_issue_id)
    session: object | None = None  # core.http_client.GiteaSession, None nếu chưa cần login


@dataclass
class CheckEntry:
    cve_id: str
    ref_id: str
    module_name: str  # "checks.cve_2022_38183" — import động trong main.py
    affected_below: tuple[int, int, int]  # version < giá trị này thì applicable
    requires_auth: bool
    required_args: list[str]  # tên attribute trên argparse.Namespace bắt buộc phải có giá trị

    def is_applicable(self, version: tuple[int, int, int]) -> bool:
        return version < self.affected_below

    def missing_args(self, args) -> list[str]:
        return [name for name in self.required_args if not getattr(args, name, None)]


ALL_CHECKS: list[CheckEntry] = [
    CheckEntry(
        cve_id="CVE-2022-42968",
        ref_id="VULN-02",
        module_name="checks.cve_2022_42968",
        affected_below=(1, 17, 3),
        requires_auth=False,
        required_args=["graph_owner", "graph_repo"],
    ),
    CheckEntry(
        cve_id="CVE-2022-38183",
        ref_id="VULN-01",
        module_name="checks.cve_2022_38183",
        affected_below=(1, 16, 9),
        requires_auth=True,
        required_args=["target_issue_id"],
    ),
    CheckEntry(
        cve_id="CVE-2024-6886",
        ref_id="VULN-03",
        module_name="checks.cve_2024_6886",
        affected_below=(1, 22, 1),
        requires_auth=True,
        required_args=[],
    ),
]
