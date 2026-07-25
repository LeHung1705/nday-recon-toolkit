"""So sánh version Gitea dạng "1.16.8+dev-123-abcdef" -> (1, 16, 8)."""
import re

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


class VersionParseError(Exception):
    """Raised khi không parse được version string trả về từ /api/v1/version."""


def parse_version(version_string: str) -> tuple[int, int, int]:
    match = _VERSION_RE.match(version_string.strip())
    if not match:
        raise VersionParseError(
            f"Không parse được version từ chuỗi '{version_string}' "
            "(kỳ vọng dạng 'X.Y.Z...')."
        )
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def less_than(version: tuple[int, int, int], target: tuple[int, int, int]) -> bool:
    """True nếu `version` < `target` (so sánh tuple chuẩn theo thứ tự semver)."""
    return version < target
