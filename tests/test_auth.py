"""Tests for the admin login, CSRF, export and unban. Uses a temporary DB and credentials
file, so it never touches your real logs/waf_events.db or admin_credentials.json.
Run:  python tests/test_auth.py"""
import csv
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_tmp = tempfile.mkdtemp()
os.environ["WAF_CREDENTIALS_FILE"] = os.path.join(_tmp, "creds.json")
from src.hybrid_waf.utils import event_store  # noqa: E402
event_store.DB_PATH = type(event_store.DB_PATH)(os.path.join(_tmp, "test.db"))   # temp DB
from src.hybrid_waf.utils import admin_auth  # noqa: E402
from app import app  # noqa: E402
from src.hybrid_waf.utils.traffic_control import get_controller  # noqa: E402

app.config["TESTING"] = True
PW = "correct-horse-battery"


def fresh_client(configured=True):
    admin_auth.login_limiter.reset()
    if configured:
        admin_auth.write_credentials("admin", PW)
    elif os.path.exists(os.environ["WAF_CREDENTIALS_FILE"]):
        os.remove(os.environ["WAF_CREDENTIALS_FILE"]); admin_auth._cache["key"] = None
    return app.test_client()


def token(c):
    html = c.get("/login").get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def login(c, user="admin", pw=PW, nxt=""):
    return c.post("/login", data={"username": user, "password": pw, "csrf_token": token(c), "next": nxt})


def test_everything_private_without_login():
    c = fresh_client()
    r = c.get("/dashboard"); assert r.status_code == 302 and "/login" in r.headers["Location"]
    for url in ("/api/stats", "/api/events", "/api/export?format=csv", "/api/bans"):
        assert c.get(url).status_code == 401, url
    assert c.post("/api/unban", json={"ip": "1.2.3.4"}).status_code == 401
    assert c.get("/home").status_code == 200 and c.get("/").status_code == 200   # public pages stay public
    assert c.post("/check_request", json={"user_request": "hello"}).json["status"] == "valid"


def test_locked_when_no_account_exists():
    c = fresh_client(configured=False)
    assert "set_admin_password.py" in c.get("/login").get_data(as_text=True)
    assert c.get("/dashboard").status_code == 302
    assert c.post("/login", data={"username": "admin", "password": "x", "csrf_token": "x"}).status_code == 400


def test_wrong_password_and_csrf():
    c = fresh_client()
    r = login(c, pw="wrong"); assert r.status_code == 401 and b"Invalid username or password" in r.data
    assert c.get("/api/stats").status_code == 401
    r = c.post("/login", data={"username": "admin", "password": PW})            # no CSRF token
    assert r.status_code == 400 and c.get("/api/stats").status_code == 401
    r = login(c, user="nobody")                                                  # same generic message
    assert r.status_code == 401 and b"Invalid username or password" in r.data


def test_lockout_after_5_failures():
    c = fresh_client()
    codes = [login(c, pw="bad").status_code for _ in range(5)]
    assert codes == [401, 401, 401, 401, 401]
    r = login(c)                                  # correct password, but locked out
    assert r.status_code == 429 and c.get("/api/stats").status_code == 401
    rows = event_store.get_events(100)
    assert any(e["rule_id"] == "AUTH-001" for e in rows) and any(e["rule_id"] == "AUTH-002" for e in rows)


def test_login_success_and_access():
    c = fresh_client()
    r = login(c); assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert c.get("/dashboard").status_code == 200
    assert c.get("/api/stats").status_code == 200 and c.get("/api/events").status_code == 200
    assert c.get("/api/bans").status_code == 200


def test_open_redirect_blocked():
    for bad in ("//evil.com", "https://evil.com", "/\\evil.com"):
        c = fresh_client()
        r = login(c, nxt=bad)
        assert r.headers["Location"].endswith("/dashboard"), (bad, r.headers["Location"])
    c = fresh_client(); r = login(c, nxt="/api/stats")
    assert r.headers["Location"].endswith("/api/stats")


def test_logout_needs_csrf_and_ends_session():
    c = fresh_client(); login(c)
    c.post("/logout", data={})                                         # no token: ignored
    assert c.get("/api/stats").status_code == 200
    with c.session_transaction() as s:
        t = s["csrf"]
    c.post("/logout", data={"csrf_token": t})
    assert c.get("/api/stats").status_code == 401


def test_password_change_logs_out_everyone():
    c = fresh_client(); login(c)
    assert c.get("/api/stats").status_code == 200
    admin_auth.write_credentials("admin", "a-brand-new-password")
    assert c.get("/api/stats").status_code == 401
    admin_auth.write_credentials("admin", PW)


def test_export_csv_json_and_formula_injection():
    c = fresh_client(); login(c)
    event_store.record_event(payload="=cmd|' /C calc'!A0", status="malicious", action="blocked",
                             detected_by="signature", client_ip="5.5.5.5", category="Other", rule_id="X-1")
    r = c.get("/api/export?format=csv&range=all")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0][0] == "id" and rows[0][-1] == "payload"
    assert any(row[-1].startswith("'=cmd") for row in rows), "formula not neutralised"
    j = c.get("/api/export?format=json&range=all")
    data = json.loads(j.get_data(as_text=True)); assert isinstance(data, list) and data
    assert c.get("/api/export?format=xml").status_code == 400


def test_unban_requires_csrf():
    c = fresh_client(); login(c)
    ctl = get_controller()
    for i in range(5):
        ctl.record_attack("9.9.9.9")
    assert any(b["ip"] == "9.9.9.9" for b in c.get("/api/bans").json)
    assert c.post("/api/unban", json={"ip": "9.9.9.9"}).status_code == 403      # no token
    with c.session_transaction() as s:
        t = s["csrf"]
    assert c.post("/api/unban", json={"ip": "9.9.9.9"}, headers={"X-CSRF-Token": t}).json["unbanned"] is True
    assert c.post("/api/unban", json={"ip": "nope"}, headers={"X-CSRF-Token": t}).status_code == 400
    assert not any(b["ip"] == "9.9.9.9" for b in c.get("/api/bans").json)


def test_security_headers_and_cookie_flags():
    c = fresh_client()
    r = c.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in r.headers["Cache-Control"]
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_credentials_validation_and_hashing():
    for bad_user, bad_pw in (("", "longenough1"), ("admin", "short"), ("admin", "ADMIN")):
        try:
            admin_auth.write_credentials(bad_user, bad_pw); raise AssertionError("accepted bad creds")
        except ValueError:
            pass
    admin_auth.write_credentials("admin", PW)
    raw = open(os.environ["WAF_CREDENTIALS_FILE"]).read()
    assert PW not in raw and ("scrypt" in raw or "pbkdf2" in raw)


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                fails += 1; print("FAIL", name, type(e).__name__, e)
    sys.exit(1 if fails else 0)
