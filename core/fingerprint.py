"""Bước 1 (Fingerprint): xác định version Gitea đang chạy qua API công khai.

Endpoint /api/v1/version không cần auth và có mặt ở mọi bản Gitea hiện đại,
nên đây là cách fingerprint an toàn nhất (không cần đoán qua banner/HTML).
"""
import requests

from .version_compare import parse_version


class FingerprintError(Exception):
    """Raised khi không lấy được version — không thể tiếp tục an toàn."""


def get_version(base_url: str, timeout: int = 10) -> tuple[str, tuple[int, int, int]]:
    """Trả về (raw_version_string, parsed_tuple).

    Kỳ vọng: response 200 JSON {"version": "1.16.8+dev-..."}
    """
    url = f"{base_url.rstrip('/')}/api/v1/version"
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        raise FingerprintError(
            f"Không kết nối được tới '{url}' để fingerprint version: {exc}"
        ) from exc

    if resp.status_code != 200:
        raise FingerprintError(
            f"'{url}' trả về status {resp.status_code} thay vì 200 — "
            "không thể xác nhận đây có phải Gitea hay không."
        )

    try:
        data = resp.json()
        raw_version = data["version"]
    except (ValueError, KeyError) as exc:
        raise FingerprintError(
            f"Response từ '{url}' không đúng format JSON kỳ vọng ({{'version': ...}}): {exc}"
        ) from exc

    parsed = parse_version(raw_version)
    return raw_version, parsed
