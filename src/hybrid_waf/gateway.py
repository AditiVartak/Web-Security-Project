"""WAFinity gateway: a reverse proxy that inspects every request before forwarding it.

Browser --> gateway (this file, port 8080) --> your real app (backend_url)

Clean requests are forwarded and the app's response is returned unchanged. Attacks get a 403
block page and never reach the app. Configure it in waf_config.json ("proxy" section).
"""
import html
import http.client
import socket
import threading
from urllib.parse import quote, urlsplit

from flask import Flask, Response, request
from werkzeug.datastructures import Headers
from werkzeug.exceptions import RequestEntityTooLarge

from src.hybrid_waf.utils.event_store import init_db, record_event
from src.hybrid_waf.utils.request_inspector import inspect_request
from src.hybrid_waf.utils.traffic_control import get_controller

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "expect"}
# Headers the gateway sets itself, so a client can't forge them.
GATEWAY_HEADERS = {"host", "content-length", "x-forwarded-for", "x-forwarded-host",
                   "x-forwarded-proto", "x-real-ip"}
STATIC_EXT = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".webp")
MAX_RESPONSE_BYTES = 20 * 1024 * 1024

_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#000;color:#fff;font-family:'Segoe UI',Arial,sans-serif}}
.box{{max-width:520px;padding:32px;border:1px solid rgba(255,77,109,.4);border-radius:16px;
background:rgba(255,255,255,.04);text-align:center}}h1{{margin:0 0 10px;color:#ff4d6d}}
p{{color:rgba(255,255,255,.75);line-height:1.5}}code{{background:rgba(255,255,255,.1);padding:2px 8px;border-radius:4px}}
small{{color:rgba(255,255,255,.45)}}</style></head><body><div class="box">
<h1>{title}</h1><p>{message}</p>{extra}<small>Protected by WAFinity</small></div></body></html>"""


def _default_ml_predict(path, query, body_text):
    from src.hybrid_waf.utils.preprocessor import extract_features
    from src.hybrid_waf.utils.ml_checker import check_ml_prediction
    return int(check_ml_prediction(extract_features(path, query, body_text))) == 1


def create_gateway_app(ml_predict=_default_ml_predict):
    traffic = get_controller()
    init_db()
    app = Flask("wafinity_gateway")
    app.config["MAX_CONTENT_LENGTH"] = int(traffic.cfg["proxy"]["max_body_bytes"])

    # ---------------------------------------------------------------- helpers
    def client_ip():
        if traffic.trust_proxy_headers:
            xff = request.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return request.remote_addr

    def page(status, title, message, request_id=None):
        # Never echo request data here: reflecting the payload would be an XSS hole in the block page.
        extra = f"<p>Reference: <code>{html.escape(request_id)}</code></p>" if request_id else ""
        return Response(_PAGE.format(title=html.escape(title), message=html.escape(message), extra=extra),
                        status=status, mimetype="text/html")

    def note_attack(ip):
        if traffic.record_attack(ip):
            ab = traffic.cfg["auto_ban"]
            record_event(payload=f"Auto-ban: {ab['max_attacks']} attacks within {ab['window_seconds']}s",
                         status="banned", action="blocked", detected_by="traffic_control",
                         client_ip=ip, category="IP Banned", rule_id="BAN-001")

    def too_large(ip):
        rid = record_event(payload=f"{request.method} {request.path} (body over limit)", status="rejected",
                           action="blocked", detected_by="gateway", client_ip=ip, method=request.method,
                           path=request.path, category="Oversized Request", rule_id="SIZE-001")
        return page(413, "413 Request Too Large", "The request body is larger than this site allows.", rid)

    # ---------------------------------------------------------------- forwarding
    def forward(pc, ip, body):
        backend = urlsplit(pc["backend_url"])
        conn_cls = http.client.HTTPSConnection if backend.scheme == "https" else http.client.HTTPConnection
        port = backend.port or (443 if backend.scheme == "https" else 80)

        target = quote(request.path, safe="/%:@!$&'()*+,;=-._~")
        if request.query_string:
            target += "?" + request.query_string.decode("latin-1")

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() not in GATEWAY_HEADERS}
        headers["Host"] = backend.netloc
        headers["X-Forwarded-For"] = ip                  # the real peer, never a client-supplied value
        headers["X-Forwarded-Host"] = request.host
        headers["X-Forwarded-Proto"] = request.scheme
        if body or request.method in ("POST", "PUT", "PATCH"):
            headers["Content-Length"] = str(len(body))

        conn = conn_cls(backend.hostname, port, timeout=float(pc["timeout_seconds"]))
        try:
            conn.request(request.method, target, body=body or None, headers=headers)
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                return page(502, "502 Bad Gateway", "The application returned too much data.")
            out = Headers()
            for key, value in resp.getheaders():
                lk = key.lower()
                if lk in HOP_BY_HOP or lk == "content-length":
                    continue
                if lk == "location" and value.startswith(f"{backend.scheme}://{backend.netloc}"):
                    value = request.host_url.rstrip("/") + value[len(f"{backend.scheme}://{backend.netloc}"):]
                out.add(key, value)          # .add keeps repeated headers (several Set-Cookie)
            return Response(data, status=resp.status, headers=out)
        except socket.timeout:
            return page(504, "504 Gateway Timeout", "The application took too long to respond.")
        except http.client.InvalidURL:
            return page(400, "400 Bad Request", "The request could not be processed.")
        except (OSError, http.client.HTTPException):
            return page(502, "502 Bad Gateway", "The protected application is not reachable.")
        finally:
            conn.close()

    # ---------------------------------------------------------------- the one route
    @app.errorhandler(RequestEntityTooLarge)
    def _too_big(_):
        return too_large(client_ip())

    @app.route("/", defaults={"path": ""}, methods=METHODS)
    @app.route("/<path:path>", methods=METHODS)
    def handle(path):
        pc = traffic.cfg["proxy"]
        ip = client_ip()

        # Stage 0: blocklist / active ban / rate limit
        decision = traffic.check(ip, scope="proxy")
        if decision.action != "allow":
            rid = None
            if traffic.should_log(ip, decision.action):
                rid = record_event(payload=f"{request.method} {request.path}", status=decision.action,
                                   action="blocked", detected_by="traffic_control", client_ip=ip,
                                   method=request.method, path=request.path,
                                   category=decision.category, rule_id=decision.rule_id)
            msg = {"rate_limited": f"Too many requests. Try again in {decision.retry_after} seconds.",
                   "banned": f"Your IP is temporarily banned. Try again in {decision.retry_after} seconds.",
                   "blocklisted": "Access denied."}[decision.action]
            resp = page(decision.http_status, f"{decision.http_status} {decision.category}", msg, rid)
            if decision.retry_after:
                resp.headers["Retry-After"] = str(decision.retry_after)
            return resp

        # Size limit
        if (request.content_length or 0) > int(pc["max_body_bytes"]):
            return too_large(ip)
        body = request.get_data()

        # Stage 1+2: inspect path, query, headers, cookies and body
        result = inspect_request(
            method=request.method, path=request.path,
            query=request.query_string.decode("latin-1"), headers=request.headers, body=body,
            ml_predict=ml_predict if pc["ml_on_obfuscated"] else None)

        if result["action"] == "block":
            evidence = f'[{result["location"]}] {result["value"]}'[:2000]
            if pc["mode"] == "block":
                rid = record_event(payload=evidence, status=result["status"], action="blocked",
                                   detected_by=result["detected_by"], client_ip=ip, method=request.method,
                                   path=request.path, category=result["category"], rule_id=result["rule_id"])
                note_attack(ip)
                return page(403, "403 Request Blocked",
                            "Your request was blocked by the web application firewall.", rid)
            # detect-only mode: record it, but let it through
            record_event(payload=evidence, status=result["status"], action="detected",
                         detected_by=result["detected_by"], client_ip=ip, method=request.method,
                         path=request.path, category=result["category"], rule_id=result["rule_id"])
        elif pc["log_allowed"] and not request.path.lower().endswith(STATIC_EXT):
            record_event(payload=f"{request.method} {request.full_path.rstrip('?')}"[:2000],
                         status=result["status"], action="allowed", detected_by=result["detected_by"],
                         client_ip=ip, method=request.method, path=request.path,
                         category="None", rule_id=result["rule_id"])

        return forward(pc, ip, body)

    return app


def start_gateway():
    """Run the gateway in a background thread of the main process, so it shares the same
    rate-limit / ban state as the dashboard (the Active Bans panel sees gateway bans)."""
    from werkzeug.serving import make_server
    pc = get_controller().cfg["proxy"]
    if not pc["enabled"]:
        return None
    try:
        server = make_server(pc["listen_host"], int(pc["listen_port"]), create_gateway_app(), threaded=True)
    except OSError as exc:
        print(f"[WAFinity] Gateway NOT started (port {pc['listen_port']} unavailable): {exc}")
        return None
    threading.Thread(target=server.serve_forever, name="wafinity-gateway", daemon=True).start()
    print(f"[WAFinity] Gateway: http://{pc['listen_host']}:{pc['listen_port']}  ->  {pc['backend_url']}"
          f"  (mode: {pc['mode']})")
    return server
