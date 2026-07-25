"""Shared data types for check results.

Kept dependency-free (stdlib only) so checks/ and core/ modules can import
this without pulling in requests/bs4 just for type definitions.
"""
from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Kết quả 1 lần analyze — KHÔNG có mức "exploited", chỉ xác nhận tồn tại."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class CheckResult:
    cve_id: str
    ref_id: str  # khớp Ref ID trong report/ gốc (VULN-01/02/03)
    risk_level: str
    wstg_ref: str
    cwe: str
    status: Status
    evidence: str = ""
    detail: str = ""
    request_repro: str = ""  # curl-equivalent để tái tạo lại đúng request đã gửi
    response_summary: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
