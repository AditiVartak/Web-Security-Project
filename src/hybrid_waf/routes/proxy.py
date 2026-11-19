import logging
import os

from flask import Blueprint, request, jsonify

from src.hybrid_waf.utils.signature_checker import inspect
from src.hybrid_waf.utils.event_store import init_db, record_event
from src.hybrid_waf.utils.traffic_control import get_controller

# --- Legacy text log (kept so nothing else breaks) ---
os.makedirs("logs", exist_ok=True)
waf_logger = logging.getLogger("waf_detections")
waf_logger.setLevel(logging.INFO)
if not waf_logger.handlers:  # avoid duplicate handlers on Flask debug reload
    fh = logging.FileHandler("logs/detections.log")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    waf_logger.addHandler(fh)

init_db()  # creates logs/waf_events.db + table if missing (and migrates old ones)

proxy_bp = Blueprint("proxy", __name__)


traffic = get_controller()

_REFUSALS = {
    "rate_limited": "Too many requests. Please slow down and try again in {n} seconds.",
    "banned": "Your IP address is temporarily banned after repeated attacks. Try again in {n} seconds.",
    "blocklisted": "Access denied: your IP address is on the blocklist.",
}


def _client_ip():
    """The caller's IP. X-Forwarded-For is attacker-controlled, so it is ignored unless
    waf_config.json sets "trust_proxy_headers": true (only do that behind your own proxy)."""
    if traffic.trust_proxy_headers:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr


def _note_attack(ip):
    """Feed a blocked attack to the auto-ban logic. Returns True if the IP just got banned."""
    if traffic.record_attack(ip):
        ab = traffic.cfg["auto_ban"]
        record_event(payload=f"Auto-ban: {ab['max_attacks']} attacks within {ab['window_seconds']}s",
                     status="banned", action="blocked", detected_by="traffic_control",
                     client_ip=ip, category="IP Banned", rule_id="BAN-001")
        return True
    return False


@proxy_bp.route("/check_request", methods=["POST"])
def check_request():
    data = request.get_json(silent=True) or {}
    user_input = data.get("user_request", "")
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")
    ip = _client_ip()

    # --- Stage 0: traffic controls (allow/block lists, active bans, rate limit) ---
    decision = traffic.check(ip)
    if decision.action != "allow":
        if traffic.should_log(ip, decision.action):
            record_event(payload=user_input, status=decision.action, action="blocked",
                         detected_by="traffic_control", client_ip=ip,
                         category=decision.category, rule_id=decision.rule_id)
        resp = jsonify({
            "status": decision.action,
            "message": _REFUSALS[decision.action].format(n=decision.retry_after),
            "retry_after": decision.retry_after,
            "category": decision.category,
            "rule_id": decision.rule_id,
        })
        resp.status_code = decision.http_status
        if decision.retry_after:
            resp.headers["Retry-After"] = str(decision.retry_after)
        return resp

    # --- Stage 1: signature rules (on the text as sent) ---
    result = inspect(user_input)
    verdict = result["verdict"]

    if verdict == "valid":
        waf_logger.info(f"{user_input!r} - valid")
        record_event(payload=user_input, status="valid", action="allowed",
                     detected_by="none", client_ip=ip, category="None")
        return jsonify({
            "status": "valid",
            "message": "All Clear! Your request passed our security checks with flying colors.✨",
        })

    if verdict == "malicious":
        waf_logger.info(f"{user_input!r} - malicious(signature:{result['rule_id']})")
        record_event(payload=user_input, status="malicious", action="blocked",
                     detected_by="signature", client_ip=ip,
                     category=result["category"], rule_id=result["rule_id"])
        banned = _note_attack(ip)
        return jsonify({
            "auto_banned": banned,
            "status": "malicious",
            "message": "Critical Alert! Malicious pattern detected in your request.<br>Access Denied!🔒",
            "category": result["category"],
            "rule_id": result["rule_id"],
        })

    # --- Stage 2: encoded/obfuscated input -> ML model + rules re-run on the decoded text ---
    from src.hybrid_waf.utils.preprocessor import extract_features
    from src.hybrid_waf.utils.ml_checker import check_ml_prediction

    features = extract_features(uri, get_data, post_data)
    ml_malicious = int(check_ml_prediction(features)) == 1
    rule_malicious = result["matched_on"] == "decoded"   # decoded text hit a signature rule
    is_malicious = ml_malicious or rule_malicious

    if ml_malicious and rule_malicious:
        detected_by = "ml+signature"
    elif rule_malicious:
        detected_by = "signature(decoded)"
    else:
        detected_by = "ml"

    waf_logger.info(f"{user_input!r} - {'malicious(' + detected_by + ')' if is_malicious else 'valid'}")
    record_event(payload=user_input, status="obfuscated",
                 action="blocked" if is_malicious else "allowed",
                 detected_by=detected_by, client_ip=ip,
                 category=result["category"] if (is_malicious or rule_malicious) else "Obfuscated",
                 rule_id=result["rule_id"])

    banned = _note_attack(ip) if is_malicious else False
    return jsonify({
        "auto_banned": banned,
        "status": "obfuscated",
        "ml_verdict": (
            "🚨 Threat Confirmed! AI Defense System Blocked Suspicious Activity.🔒"
            if is_malicious else
            "✅ Advanced AI Scan Complete: Request Verified Safe ✨"
        ),
        "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
        "features": features,
        "category": result["category"],
        "rule_id": result["rule_id"],
    })
