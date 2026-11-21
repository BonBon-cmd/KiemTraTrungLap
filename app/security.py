"""Xác thực: băm mật khẩu bcrypt, JWT, chống dò mật khẩu.

Không chứa quy tắc phân quyền - phần đó nằm ở app/permissions.py.
"""
from collections import deque
from datetime import datetime, timedelta, timezone
from threading import Lock
from time import monotonic
import os
import re

import bcrypt
import jwt

JWT_ALGORITHM = "HS256"
COOKIE_NAME = "access_token"
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
# bcrypt chỉ dùng 72 byte đầu của mật khẩu; từ chối thay vì cắt âm thầm.
MAX_PASSWORD_BYTES = 72
# Hệ số công việc bcrypt. Mặc định 12 (khuyến nghị hiện nay); chỉ hạ thấp trong môi trường test.
BCRYPT_ROUNDS = max(4, min(16, int(os.getenv("BCRYPT_ROUNDS", "12"))))


class PasswordError(ValueError):
    pass


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if len(email) > 254 or not EMAIL_PATTERN.match(email):
        raise ValueError("Email không hợp lệ.")
    return email


def validate_password(password: str, minimum: int, email: str = ""):
    if len(password) < minimum:
        raise PasswordError(f"Mật khẩu phải có ít nhất {minimum} ký tự.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordError(f"Mật khẩu tối đa {MAX_PASSWORD_BYTES} byte.")
    if email and password.lower() == email.lower():
        raise PasswordError("Mật khẩu không được trùng email.")
    if password.isdigit() or len(set(password)) < 4:
        raise PasswordError("Mật khẩu quá dễ đoán.")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")


# Băm giả để thời gian phản hồi khi email không tồn tại gần bằng khi sai mật khẩu.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


def verify_password(password: str, password_hash: str | None) -> bool:
    candidate = password.encode("utf-8")
    if len(candidate) > MAX_PASSWORD_BYTES:
        bcrypt.checkpw(b"x", _DUMMY_HASH.encode("ascii"))
        return False
    try:
        return bcrypt.checkpw(candidate, (password_hash or _DUMMY_HASH).encode("ascii")) and password_hash is not None
    except ValueError:
        return False


def create_access_token(secret: str, user, minutes: int) -> str:
    issued = datetime.now(timezone.utc)
    claims = {
        "sub": user.id, "tv": user.token_version,
        "iat": issued, "exp": issued + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(secret: str, token: str) -> dict | None:
    """Trả claims hợp lệ hoặc None. Pin thuật toán và bắt buộc có exp/sub."""
    try:
        return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "sub", "tv"]})
    except jwt.PyJWTError:
        return None


class LoginLimiter:
    """Khóa tạm theo (email, IP) sau nhiều lần sai liên tiếp. Bộ nhớ trong tiến trình:
    phù hợp triển khai một tiến trình; nhiều tiến trình cần chuyển sang Redis/PostgreSQL."""

    def __init__(self, max_failures=5, window_seconds=900, max_keys=10000):
        self.max_failures, self.window, self.max_keys = max_failures, window_seconds, max_keys
        self._failures: dict[tuple, deque] = {}
        self._lock = Lock()

    def _prune(self, key, now):
        events = self._failures.get(key)
        while events and now - events[0] > self.window:
            events.popleft()
        if events is not None and not events:
            del self._failures[key]

    def retry_after(self, key) -> int:
        """Số giây còn bị khóa, 0 nếu được phép thử."""
        now = monotonic()
        with self._lock:
            self._prune(key, now)
            events = self._failures.get(key)
            if events and len(events) >= self.max_failures:
                return max(1, int(self.window - (now - events[0])))
            return 0

    def record_failure(self, key):
        now = monotonic()
        with self._lock:
            if key not in self._failures and len(self._failures) >= self.max_keys:
                self._failures.pop(next(iter(self._failures)))  # chặn tăng bộ nhớ vô hạn
            self._failures.setdefault(key, deque()).append(now)
            self._prune(key, now)

    def reset(self, key):
        with self._lock:
            self._failures.pop(key, None)
