import csv
import io
import ipaddress
import json
from datetime import datetime

from flask import Blueprint, Response, jsonify, render_template, request

from src.hybrid_waf.utils.admin_auth import csrf_protected, csrf_token, login_required
from src.hybrid_waf.utils.event_store import export_events, get_events, get_stats
from src.hybrid_waf.utils.traffic_control import get_controller

main_bp = Blueprint('main', __name__)


# ---------------- public pages ----------------
@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/home')
def home():
    return render_template('home.html')


# ---------------- admin only ----------------
@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', csrf_token=csrf_token())


@main_bp.route('/api/stats')
@login_required
def api_stats():
    """?range=1h|24h|7d|all  (default 24h)"""
    return jsonify(get_stats(request.args.get('range', '24h')))


@main_bp.route('/api/events')
@login_required
def api_events():
    """?limit=50&after_id=0&blocked=1  (after_id lets the live feed fetch only new rows)"""
    try:
        limit = int(request.args.get('limit', 50))
        after_id = int(request.args.get('after_id', 0))
    except ValueError:
        return jsonify({"error": "limit and after_id must be integers"}), 400
    return jsonify(get_events(limit, after_id, request.args.get('blocked') == '1'))


_CSV_COLUMNS = ["id", "request_id", "ts", "client_ip", "method", "path", "status", "action",
                "detected_by", "category", "rule_id", "ml_score", "payload"]


def _csv_safe(value):
    """Stop spreadsheet formula injection: payloads are attacker-controlled, and a cell that
    starts with = + - @ would be executed as a formula when the CSV is opened in Excel."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


@main_bp.route('/api/export')
@login_required
def api_export():
    """?format=csv|json&range=1h|24h|7d|all"""
    fmt = request.args.get('format', 'csv').lower()
    if fmt not in ('csv', 'json'):
        return jsonify({"error": "format must be csv or json"}), 400
    rows = export_events(request.args.get('range', '24h'))
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    headers = {"Content-Disposition": f'attachment; filename="waf_events_{stamp}.{fmt}"'}

    if fmt == 'json':
        return Response(json.dumps(rows, indent=2), mimetype='application/json', headers=headers)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for r in rows:
        writer.writerow([_csv_safe(r.get(c)) for c in _CSV_COLUMNS])
    return Response(buf.getvalue(), mimetype='text/csv', headers=headers)


@main_bp.route('/api/bans')
@login_required
def api_bans():
    bans = get_controller().active_bans()
    return jsonify([{"ip": ip, "seconds_left": left}
                    for ip, left in sorted(bans.items(), key=lambda kv: -kv[1])])


@main_bp.route('/api/unban', methods=['POST'])
@login_required
@csrf_protected
def api_unban():
    ip = (request.get_json(silent=True) or {}).get('ip', '')
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "invalid IP address"}), 400
    return jsonify({"ip": ip, "unbanned": get_controller().unban(ip)})
