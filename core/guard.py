"""Target whitelist guard — bước bắt buộc chạy TRƯỚC bất kỳ request nào khác.

Nguyên tắc scope: tool này chỉ được phép chạy nhắm vào lab Docker local của
chính người dùng. Nếu hostname không nằm trong whitelist, toàn bộ chương
trình phải dừng lại ngay, không gửi bất kỳ request nào khác.
"""
from urllib.parse import urlparse

# Các host luôn được coi là "lab local" — không cần khai báo thêm.
_DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class TargetNotAllowedError(Exception):
    """Raised khi target URL không phải localhost/host đã whitelist."""


def validate_target(url: str, extra_allowed_hosts: list[str] | None = None) -> str:
    """Kiểm tra `url` có hợp lệ để tool được phép chạy hay không.

    Trả về hostname đã validate (để log lại), hoặc raise TargetNotAllowedError.
    """
    extra_allowed_hosts = extra_allowed_hosts or []
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise TargetNotAllowedError(
            f"URL '{url}' thiếu scheme http/https hợp lệ — không thể xác định target an toàn."
        )

    hostname = parsed.hostname
    if not hostname:
        raise TargetNotAllowedError(f"Không parse được hostname từ URL '{url}'.")

    allowed = _DEFAULT_ALLOWED_HOSTS | set(extra_allowed_hosts)
    if hostname.lower() not in {h.lower() for h in allowed}:
        raise TargetNotAllowedError(
            f"Host '{hostname}' KHÔNG nằm trong whitelist (localhost/127.0.0.1/"
            f"::1{', hoặc ' + ', '.join(extra_allowed_hosts) if extra_allowed_hosts else ''}). "
            "Tool này chỉ được phép chạy trên lab Docker local — từ chối chạy để "
            "tránh test nhầm vào hệ thống không có quyền truy cập. Nếu đây thực sự "
            "là lab nội bộ đã được cấp phép, dùng flag --allow-host để thêm vào whitelist."
        )

    return hostname
