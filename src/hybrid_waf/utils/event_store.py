"""SQLite-backed event store for WAF detections (Step 1 of the dashboard)."""
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

# <repo>/logs/waf_events.db  (works no matter where you run `python app.py` from)
BASE_DIR = Path(__file__).resolve().parents[3]
DB_PATH = BASE_DIR / "logs" / "waf_events.db"

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT NOT NULL,
    ts          TEXT NOT NULL,          -- ISO 8601, e.g. 2026-10-15T14:03:22
    client_ip   TEXT,
    method      TEXT,
    path        TEXT,
    payload     TEXT,
    status      TEXT NOT NULL,          -- valid | malicious | obfuscated
    action      TEXT NOT NULL,          -- allowed | blocked
    detected_by TEXT,                   -- signature | ml | none
    category    TEXT,                   -- SQLi | XSS | SSRF | HTML Injection | Obfuscated | Other | None
    ml_score    REAL,
    rule_id     TEXT                    -- e.g. SQLI-001 (NULL for valid/ML-only)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
"""

# Lightweight categorizer (the signature checker only returns a verdict, not a type)
_CATEGORY_RULES = [
    ("SQLi", r"\b(union|select|insert|drop|delete|update)\b.*\bfrom\b|\bunion\s+select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bsleep\s*\(|\bwaitfor\b|\bbenchmark\s*\(|--|/\*"),
    ("XSS", r"<\s*script|<\s*img|<\s*svg|<\s*iframe|on\w+\s*=|javascript:|document\.cookie|alert\s*\(|eval\s*\("),
    ("SSRF", r"file://|gopher://|169\.254\.|127\.0\.0\.1|localhost|metadata\.google"),
    ("HTML Injection", r"<\s*(div|span|form|input|body|html|table|style|a)\b"),
]


def categorize(payload: str, status: str) -> str:
    if status == "valid":
        return "None"
    for name, pattern in _CATEGORY_RULES:
        if re.search(pattern, payload or "", re.IGNORECASE):
            return name
    return "Obfuscated" if status == "obfuscated" else "Other"


@contextmanager
def _connect():
    """Open a connection, commit on success, and ALWAYS close it (important on Windows)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _lock, _connect() as conn:
        conn.executescript(SCHEMA)
        # Existing databases from Step 1/2 lack rule_id: add it without losing data.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
        if "rule_id" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN rule_id TEXT")


def record_event(*, payload, status, action, detected_by, client_ip=None,
                 method="POST", path="/check_request", ml_score=None,
                 category=None, rule_id=None) -> str:
    """Insert one event and return its request_id.

    category/rule_id come from the rule engine; if category is omitted we fall back
    to the old regex guess in categorize().
    """
    request_id = uuid.uuid4().hex[:12]
    if category is None:
        category = categorize(payload, status)
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT INTO events (request_id, ts, client_ip, method, path, payload,
                                   status, action, detected_by, category, ml_score, rule_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (request_id, datetime.now().isoformat(timespec="seconds"), client_ip,
             method, path, (payload or "")[:2000], status, action, detected_by,
             category, ml_score, rule_id),
        )
    return request_id


# ---------------------------------------------------------------------------
# Step 2: read-side helpers used by the dashboard API
# ---------------------------------------------------------------------------
from datetime import timedelta

# range -> (how far back, timeline bucket = length of the ISO timestamp prefix)
#   ts looks like 2026-10-15T10:58:09
#   [:16] -> per minute, [:13] -> per hour, [:10] -> per day
_RANGES = {
    "1h":  (timedelta(hours=1),  16),
    "24h": (timedelta(hours=24), 13),
    "7d":  (timedelta(days=7),   10),
    "all": (None,                10),
}


def _since(range_key):
    delta, _ = _RANGES.get(range_key, _RANGES["24h"])
    return (datetime.now() - delta).isoformat(timespec="seconds") if delta else None


def get_stats(range_key="24h") -> dict:
    range_key = range_key if range_key in _RANGES else "24h"
    bucket_len = _RANGES[range_key][1]
    since = _since(range_key)
    where, params = ("WHERE ts >= ?", [since]) if since else ("", [])
    blocked_where = (where + " AND " if where else "WHERE ") + "action = 'blocked'"

    with _lock, _connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        blocked = conn.execute(f"SELECT COUNT(*) FROM events {blocked_where}", params).fetchone()[0]

        categories = {r["category"]: r["n"] for r in conn.execute(
            f"SELECT category, COUNT(*) n FROM events {blocked_where} "
            "GROUP BY category ORDER BY n DESC", params)}

        detectors = {r["detected_by"]: r["n"] for r in conn.execute(
            f"SELECT detected_by, COUNT(*) n FROM events {blocked_where} "
            "GROUP BY detected_by", params)}

        top_ips = [dict(r) for r in conn.execute(
            f"SELECT client_ip ip, COUNT(*) n FROM events {blocked_where} "
            "GROUP BY client_ip ORDER BY n DESC LIMIT 5", params)]

        timeline = [dict(r) for r in conn.execute(
            f"SELECT substr(ts,1,{bucket_len}) bucket, COUNT(*) total, "
            "SUM(action='blocked') blocked "
            f"FROM events {where} GROUP BY bucket ORDER BY bucket", params)]

    return {
        "range": range_key,
        "total": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "block_ratio": round(blocked / total * 100, 1) if total else 0.0,
        "categories": categories,
        "detectors": detectors,
        "top_ips": top_ips,
        "timeline": timeline,
    }


def get_events(limit=50, after_id=0, only_blocked=False) -> list:
    """Newest first. Pass after_id to fetch only rows newer than the last one the UI has."""
    limit = max(1, min(int(limit), 500))
    clauses, params = ["id > ?"], [int(after_id)]
    if only_blocked:
        clauses.append("action = 'blocked'")
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, request_id, ts, client_ip, method, path, payload, status, "
            "action, detected_by, category, ml_score, rule_id FROM events "
            f"WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
            params + [limit]).fetchall()
    return [dict(r) for r in rows]


def export_events(range_key="24h", max_rows=50_000) -> list:
    """All events in the time range, oldest first (for CSV/JSON export)."""
    range_key = range_key if range_key in _RANGES else "24h"
    since = _since(range_key)
    where, params = ("WHERE ts >= ?", [since]) if since else ("", [])
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, request_id, ts, client_ip, method, path, payload, status, action, "
            f"detected_by, category, ml_score, rule_id FROM events {where} ORDER BY id LIMIT ?",
            params + [int(max_rows)]).fetchall()
    return [dict(r) for r in rows]
