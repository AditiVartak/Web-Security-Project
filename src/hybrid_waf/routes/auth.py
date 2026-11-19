from flask import Blueprint, redirect, render_template, request, url_for

from src.hybrid_waf.utils.admin_auth import (
    csrf_token, is_authenticated, load_credentials, login_limiter, login_user,
    safe_next, verify_csrf, verify_login)
from src.hybrid_waf.utils.event_store import record_event
from src.hybrid_waf.utils.traffic_control import get_controller

auth_bp = Blueprint("auth", __name__)


def _ip():
    t = get_controller()
    if t.trust_proxy_headers:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr


def _page(error=None, status=200):
    return render_template("login.html", csrf_token=csrf_token(), error=error,
                           configured=load_credentials() is not None,
                           next=request.values.get("next", "")), status


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if is_authenticated():
            return redirect(url_for("main.dashboard"))
        return _page()

    ip = _ip()
    if not verify_csrf(request.form.get("csrf_token")):
        return _page("Your session expired. Please try again.", 400)

    wait = login_limiter.locked_for(ip)
    if wait:
        return _page(f"Too many failed attempts. Try again in {wait} seconds.", 429)

    username = request.form.get("username", "")
    if verify_login(username, request.form.get("password", "")):
        login_limiter.reset(ip)
        login_user()
        return redirect(safe_next(request.form.get("next"), url_for("main.dashboard")))

    # Failed login: log it (these are security events) and count toward lockout.
    record_event(payload=f"Failed admin login for user {username[:50]!r}", status="login_failed",
                 action="blocked", detected_by="auth", client_ip=ip,
                 category="Auth Failure", rule_id="AUTH-001", path="/login")
    if login_limiter.fail(ip):
        record_event(payload="Admin login locked out after repeated failures", status="login_failed",
                     action="blocked", detected_by="auth", client_ip=ip,
                     category="Auth Lockout", rule_id="AUTH-002", path="/login")
    return _page("Invalid username or password.", 401)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    from flask import session
    if verify_csrf(request.form.get("csrf_token")):
        session.clear()
    return redirect(url_for("auth.login"))
