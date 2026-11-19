import os
from datetime import timedelta

from flask import Flask, request

from src.hybrid_waf.gateway import start_gateway
from src.hybrid_waf.routes.auth import auth_bp
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp  # Import proxy Blueprint
from src.hybrid_waf.utils.admin_auth import get_secret_key

app = Flask(__name__)
app.config.update(
    SECRET_KEY=get_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,            # JavaScript can't read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",           # not sent on cross-site POSTs
    SESSION_COOKIE_SECURE=os.environ.get("WAF_HTTPS") == "1",   # set WAF_HTTPS=1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)
app.register_blueprint(auth_bp)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")          # stop clickjacking of the admin UI
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith(("/api/", "/dashboard", "/login")):
        resp.headers["Cache-Control"] = "no-store"              # don't cache admin data
    return resp


if __name__ == '__main__':
    debug = True
    # Flask's debug reloader runs this file twice; start the gateway only in the process that serves.
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_gateway()
    app.run(debug=debug)
