#!/usr/bin/env python3
"""Gitea N-day Detection Toolset — CLI orchestrator.

Luồng: guard target -> fingerprint version -> với mỗi CVE đã đăng ký trong
checks/registry.py, kiểm tra applicability + tham số cần thiết -> analyze ->
gom kết quả -> xuất report markdown.

CHỈ recon + analyze. Xem CLAUDE.md để biết đầy đủ nguyên tắc scope.
"""
import argparse
import importlib
import os
import sys
from datetime import datetime

# Console Windows mặc định dùng cp1252, không encode được tiếng Việt có dấu
# trong help text/log — ép stdout/stderr sang UTF-8 nếu runtime hỗ trợ.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

from checks.registry import ALL_CHECKS, CheckContext
from core.fingerprint import FingerprintError, get_version
from core.guard import TargetNotAllowedError, validate_target
from core.http_client import AuthError, GiteaSession
from core.models import CheckResult, Status
from core.reporter import write_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gitea N-day Detection Toolset (recon + analyze only, lab-only)."
    )
    parser.add_argument("--url", required=True, help="Base URL Gitea, vd http://localhost:3002")
    parser.add_argument("--username", help="Username để auto-login (cần cho CVE-2022-38183, CVE-2024-6886)")
    parser.add_argument("--password", help="Password để auto-login")
    parser.add_argument("--target-issue-id", type=int, help="[CVE-2022-38183] issue_id của repo private người khác dùng để test IDOR")
    parser.add_argument("--graph-owner", help="[CVE-2022-42968] owner của repo public dùng để test /graph")
    parser.add_argument("--graph-repo", help="[CVE-2022-42968] tên repo public dùng để test /graph")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout (giây), mặc định 10")
    parser.add_argument("--output", help="Đường dẫn file report markdown (mặc định tự sinh trong reports/)")
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="Thêm hostname nội bộ đã whitelist ngoài localhost/127.0.0.1 (có thể lặp lại flag)",
    )
    return parser.parse_args()


def not_applicable_result(entry) -> CheckResult:
    return CheckResult(
        cve_id=entry.cve_id,
        ref_id=entry.ref_id,
        risk_level="-",
        wstg_ref="-",
        cwe="-",
        status=Status.NOT_APPLICABLE,
        detail="Version fingerprint được không nằm trong range bị ảnh hưởng của CVE này.",
    )


def missing_input_result(entry, missing: list[str], reason: str) -> CheckResult:
    return CheckResult(
        cve_id=entry.cve_id,
        ref_id=entry.ref_id,
        risk_level="-",
        wstg_ref="-",
        cwe="-",
        status=Status.INCONCLUSIVE,
        detail=f"{reason}: {', '.join(missing) if missing else ''}".strip(": "),
    )


def error_result(entry, exc: Exception) -> CheckResult:
    return CheckResult(
        cve_id=entry.cve_id,
        ref_id=entry.ref_id,
        risk_level="-",
        wstg_ref="-",
        cwe="-",
        status=Status.INCONCLUSIVE,
        detail=f"Lỗi không xử lý được trong lúc analyze: {exc}",
    )


def main() -> int:
    args = parse_args()

    # Bước 0: guard — không cho chạy nếu target không phải lab local đã whitelist.
    try:
        validate_target(args.url, extra_allowed_hosts=args.allow_host)
    except TargetNotAllowedError as exc:
        print("=" * 70)
        print("TỪ CHỐI CHẠY — TARGET KHÔNG HỢP LỆ")
        print("=" * 70)
        print(str(exc))
        return 2

    # Bước 1: fingerprint version.
    try:
        raw_version, parsed_version = get_version(args.url, timeout=args.timeout)
    except FingerprintError as exc:
        print(f"[FATAL] Không fingerprint được version — dừng chương trình: {exc}")
        return 1

    print(f"[*] Target: {args.url}")
    print(f"[*] Fingerprinted version: {raw_version}")

    # Session dùng chung cho mọi check (anonymous by default), chỉ login khi
    # gặp check đầu tiên cần auth.
    session = GiteaSession(args.url, timeout=args.timeout)

    results: list[CheckResult] = []

    for entry in ALL_CHECKS:
        print(f"\n[*] Checking {entry.cve_id} ({entry.ref_id})...")

        if not entry.is_applicable(parsed_version):
            print(f"    -> not applicable (version {raw_version} không < {entry.affected_below})")
            results.append(not_applicable_result(entry))
            continue

        if entry.requires_auth and not (args.username and args.password):
            print("    -> inconclusive: thiếu --username/--password")
            results.append(missing_input_result(entry, [], "Yêu cầu auth nhưng thiếu --username/--password"))
            continue

        missing = entry.missing_args(args)
        if missing:
            print(f"    -> inconclusive: thiếu tham số {missing}")
            results.append(missing_input_result(entry, missing, "Thiếu tham số bắt buộc"))
            continue

        if entry.requires_auth and not session.logged_in:
            try:
                session.login(args.username, args.password)
                print(f"    -> đăng nhập thành công với user '{args.username}'")
            except AuthError as exc:
                print(f"    -> inconclusive: login thất bại ({exc})")
                results.append(missing_input_result(entry, [], f"Login thất bại: {exc}"))
                continue

        ctx = CheckContext(
            base_url=args.url,
            timeout=args.timeout,
            args=args,
            session=session,
        )

        try:
            module = importlib.import_module(entry.module_name)
            result = module.analyze(ctx)
        except Exception as exc:  # noqa: BLE001 — cố tình bắt rộng để không crash cả run
            print(f"    -> inconclusive: {exc}")
            results.append(error_result(entry, exc))
            continue

        print(f"    -> {result.status.value}")
        results.append(result)

    # Bước 4: report.
    output_path = args.output
    if not output_path:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join("reports", f"gitea_nday_report_{timestamp}.md")

    write_report(args.url, raw_version, results, output_path)
    print(f"\n[*] Report đã ghi tại: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
