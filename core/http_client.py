"""HTTP session wrapper dùng chung cho mọi module: quản lý login + CSRF.

Thiết kế: 1 GiteaSession bọc quanh requests.Session, chỉ login (CSRF flow) khi
module thực sự cần auth — các module không cần auth (vd CVE-2022-42968) vẫn
có thể dùng session này ở trạng thái anonymous.
"""
import re

import requests
from bs4 import BeautifulSoup

_CSRF_INPUT_RE = re.compile(r'name="_csrf"\s+value="([^"]+)"')
# Gitea >= 1.22: trang không có form (vd trang chủ sau khi login) không nhúng
# <input name="_csrf"> nữa, chỉ còn JS var `csrfToken: '...'` trong <script>.
_CSRF_JS_VAR_RE = re.compile(r"csrfToken:\s*'([^']+)'")


class AuthError(Exception):
    """Raised khi login thất bại (sai creds, hoặc CSRF flow của bản Gitea này khác)."""


class GiteaSession:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self._csrf_token: str | None = None
        self.logged_in = False
        self._username: str | None = None
        self._password: str | None = None

    def _extract_csrf(self, html: str) -> str:
        # Gitea nhúng CSRF theo 2 dạng tuỳ trang: <input name="_csrf"> trên form
        # login, hoặc <meta name="_csrf" content="..."> trên mọi trang đã login.
        soup = BeautifulSoup(html, "html.parser")
        input_tag = soup.find("input", attrs={"name": "_csrf"})
        if input_tag and input_tag.get("value"):
            return input_tag["value"]
        meta_tag = soup.find("meta", attrs={"name": "_csrf"})
        if meta_tag and meta_tag.get("content"):
            return meta_tag["content"]
        match = _CSRF_INPUT_RE.search(html)
        if match:
            return match.group(1)
        match = _CSRF_JS_VAR_RE.search(html)
        if match:
            return match.group(1)
        raise AuthError(
            "Không tìm thấy _csrf (input hoặc meta tag) trong trang — có thể "
            "bản Gitea này đổi cơ chế CSRF, cần cập nhật lại http_client.py."
        )

    def extract_csrf_from_html(self, html: str) -> str:
        """Public wrapper — dùng khi module cần csrf token từ 1 trang cụ thể
        (vd form tạo project) thay vì trang /user/login mặc định."""
        return self._extract_csrf(html)

    def fetch_csrf(self, path: str = "/user/login") -> str:
        """Lấy csrf token hiện tại (dùng cho cả login lẫn các form POST khác)."""
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        token = self._extract_csrf(resp.text)
        self._csrf_token = token
        return token

    @property
    def csrf_token(self) -> str:
        if self._csrf_token is None:
            return self.fetch_csrf()
        return self._csrf_token

    def login(self, username: str, password: str) -> None:
        """Tự động login: GET /user/login lấy CSRF, POST credentials.

        Xác nhận thành công bằng cookie session `i_like_gitea` xuất hiện sau
        khi POST — đây là cookie tên riêng của Gitea, không phải session
        cookie chung chung nên là tín hiệu đáng tin cậy.
        """
        csrf = self.fetch_csrf("/user/login")
        resp = self.session.post(
            f"{self.base_url}/user/login",
            data={
                "_csrf": csrf,
                "user_name": username,
                "password": password,
                "remember": "off",
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        resp.raise_for_status()

        if "i_like_gitea" not in self.session.cookies.get_dict():
            raise AuthError(
                f"Login thất bại cho user '{username}' — không thấy cookie "
                "session 'i_like_gitea' sau khi POST /user/login. Kiểm tra lại "
                "username/password."
            )

        self.logged_in = True
        self._username = username
        self._password = password
        # CSRF token đổi sau khi login (gắn với session mới). Invalidate cache
        # để lần truy cập .csrf_token tiếp theo tự refetch từ trang hiện tại
        # (module gọi entrypoint sẽ tự fetch_csrf() từ path phù hợp nếu cần).
        self._csrf_token = None

    def get(self, path: str, **kwargs):
        return self.session.get(f"{self.base_url}{path}", timeout=self.timeout, **kwargs)

    def post(self, path: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(f"{self.base_url}{path}", **kwargs)

    def delete(self, path: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.delete(f"{self.base_url}{path}", **kwargs)

    def patch(self, path: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.patch(f"{self.base_url}{path}", **kwargs)

    def api_json(self, method: str, path: str, json_body: dict | None = None):
        """Gọi /api/v1/... bằng HTTP Basic Auth (username/password đã login).

        Đã verify trên cả 2 bản Gitea trong scope: cookie session + CSRF header
        hoạt động trên 1.16.8 nhưng bị 1.22.0 từ chối thẳng ("token is
        required") — API ở bản mới không còn chấp nhận session cookie nữa.
        Basic Auth là cách chung nhất hoạt động ổn định trên cả 2 bản.
        """
        return self.session.request(
            method,
            f"{self.base_url}{path}",
            json=json_body,
            auth=(self._username, self._password),
            timeout=self.timeout,
        )
