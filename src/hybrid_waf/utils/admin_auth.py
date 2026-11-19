"""Admin authentication helpers: credential file, sessions, CSRF tokens, login throttling.

Credentials live in admin_credentials.json (created by `python set_admin_password.py`):
  {"username": ..., "password_hash": <scrypt hash>, "secret_key": <random>}
The password itself is never stored. If the file doesn't exist, nobody can log in.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parents[3]
MIN_PASSWORD_LENGTH = 8


def credentials_path() -> Path:
    return Path(os.environ.get("WAF_CREDENTIALS_FILE") or BASE_DIR / "admin_credentials.json")


# ---------------------------------------------------------------- credential file
_cache = {"key": None, "data": None}


def load_credentials():
    p = credentials_path()
    try:
        st = p.stat()
    except OSError:
        return None
    key = (str(p), st.st_mtime_ns, st.st_size)
    if _cache["key"] == key:
        return _cache["data"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not (data.get("username") and data.get("password_hash")):
            data = None
    except (OSError, ValueError):
        data = None
    _cache.update(key=key, data=data)
    return data


def write_credentials(username: str, password: str) -> None:
    username = (username or "").strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if password.lower() == username.lower():
        raise ValueError("Password must not be the same as the username.")
    existing = load_credentials() or {}
    data = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "secret_key": existing.get("secret_key") or secrets.token_hex(32),
    }
    p = credentials_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)       # owner-only on Linux/macOS (no-op on Windows)
    except OSError:
        pass
    os.replace(tmp, p)
    _cache["key"] = None


def get_secret_key() -> str:
    """Flask session-signing key: env var > credentials file > random (sessions end on restart)."""
    return (os.environ.get("WAF_SECRET_KEY")
            or (load_credentials() or {}).get("secret_key")
            or secrets.token_hex(32))


def _fingerprint(data) -> str:
    return hashlib.sha256(data["password_hash"].encode()).hexdigest()[:16]


def verify_login(username: str, password: str) -> bool:
    data = load_credentials()
    if not data:
        return False
    # Evaluate BOTH checks every time so response time doesn't reveal if the username exists.
    user_ok = hmac.compare_digest((username or "").encode(), data["username"].encode())
    pw_ok = check_password_hash(data["password_hash"], password or "")
    return user_ok and pw_ok


# ---------------------------------------------------------------- sessions
def login_user() -> None:
    data = load_credentials()
    session.clear()                       # new session id on login (prevents session fixation)
    session["user"] = data["username"]
    session["pv"] = _fingerprint(data)    # changing the password logs everyone out
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


def is_authenticated() -> bool:
    data = load_credentials()
    return bool(data and session.get("user") == data["username"]
                and session.get("pv") == _fingerprint(data))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------- CSRF
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def verify_csrf(supplied) -> bool:
    expected = session.get("csrf")
    return bool(expected and supplied and hmac.compare_digest(str(supplied), expected))


def csrf_protected(view):
    """For state-changing API calls: require the token in an X-CSRF-Token header."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not verify_csrf(request.headers.get("X-CSRF-Token")):
            return jsonify({"error": "invalid or missing CSRF token"}), 403
        return view(*args, **kwargs)
    return wrapped


def safe_next(target, default):
    """Only allow redirects to paths on this site (blocks open-redirect via ?next=//evil.com)."""
    if target and target.startswith("/") and not target.startswith("//") \
            and "\\" not in target and not urlparse(target).netloc:
        return target
    return default


# ---------------------------------------------------------------- login throttling
class LoginLimiter:
    """5 failed logins from one IP in 5 minutes -> that IP is locked out for 5 minutes."""

    def __init__(self, max_fail=5, window=300, lock=300):
        self.max_fail, self.window, self.lock = max_fail, window, lock
        self._fails, self._locked = {}, {}
        self._mutex = threading.Lock()

    def locked_for(self, ip, now=None) -> int:
        now = time.time() if now is None else now
        with self._mutex:
            until = self._locked.get(ip, 0)
            if until > now:
                return int(until - now) + 1
            self._locked.pop(ip, None)
            return 0

    def fail(self, ip, now=None) -> bool:
        """Record a failure; True if this one triggered a lockout."""
        now = time.time() if now is None else now
        with self._mutex:
            q = self._fails.setdefault(ip, deque(maxlen=self.max_fail))
            while q and now - q[0] >= self.window:
                q.popleft()
            q.append(now)
            if len(q) >= self.max_fail:
                self._locked[ip] = now + self.lock
                q.clear()
                return True
            return False

    def reset(self, ip=None):
        with self._mutex:
            if ip is None:
                self._fails.clear(); self._locked.clear()
            else:
                self._fails.pop(ip, None); self._locked.pop(ip, None)


login_limiter = LoginLimiter()
