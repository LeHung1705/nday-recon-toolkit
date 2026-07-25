"""Bước 4 (Report): gom kết quả tất cả CVE, xuất markdown theo format WSTG."""
from datetime import datetime, timezone

from .models import CheckResult, Status

_STATUS_LABEL = {
    Status.VULNERABLE: "🔴 VULNERABLE",
    Status.NOT_VULNERABLE: "🟢 NOT VULNERABLE",
    Status.INCONCLUSIVE: "🟡 INCONCLUSIVE",
    Status.NOT_APPLICABLE: "⚪ NOT APPLICABLE (version không nằm trong range ảnh hưởng)",
}


def _summary_table(results: list[CheckResult]) -> str:
    lines = ["| Ref ID | CVE | Risk Level | Status |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.ref_id} | {r.cve_id} | {r.risk_level} | {_STATUS_LABEL[r.status]} |")
    return "\n".join(lines)


def _finding_block(r: CheckResult) -> str:
    refs = "\n".join(f"- {ref}" for ref in r.references) if r.references else "- (không có)"
    return f"""### {r.ref_id}: {r.cve_id}

- **Status:** {_STATUS_LABEL[r.status]}
- **Risk Level:** {r.risk_level}
- **WSTG Ref:** {r.wstg_ref}
- **CWE:** {r.cwe}

**Detail:**

{r.detail or "(không có)"}

**Evidence:**

```
{r.evidence or "(không có)"}
```

**Steps to Reproduce (request thật đã gửi):**

```
{r.request_repro or "(không có)"}
```

**Response:**

```
{r.response_summary or "(không có)"}
```

**Remediation:**

{r.remediation or "(không có)"}

**References:**

{refs}
"""


def generate_markdown(
    target_url: str,
    fingerprinted_version: str,
    results: list[CheckResult],
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""# Gitea N-day Detection Report

- **Target:** {target_url}
- **Fingerprinted version:** {fingerprinted_version}
- **Generated at:** {generated_at}
- **Methodology:** Recon (fingerprint version) + Analyze (gửi 1 request payload,
  so sánh với baseline) theo OWASP WSTG. Đây là tool xác nhận tồn tại lỗ hổng
  (recon+analyze), KHÔNG thực hiện khai thác/leo thang.

## Summary

{_summary_table(results)}

## Findings
"""
    blocks = "\n".join(_finding_block(r) for r in results)
    return header + "\n" + blocks


def write_report(target_url: str, fingerprinted_version: str, results: list[CheckResult], output_path: str) -> None:
    content = generate_markdown(target_url, fingerprinted_version, results)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
