"""Traffic controls: per-IP rate limiting, auto-ban, and allow/block lists.

Everything lives in memory (no Redis needed). That means counters reset when the app
restarts and are NOT shared between several server processes - fine for a single-process
project, and worth stating in the README.
"""
import ipaddress
import json
import math
import threading
import time
from collections import deque
from pathlib import Path
from typing import NamedTuple, Optional

BASE_DIR = Path(__file__).resolve().parents[3]
CONFIG_PATH = BASE_DIR / "waf_config.json"

DEFAULT_CONFIG = {
    "rate_limit": {"enabled": True, "max_requests": 30, "window_seconds": 60},
    "auto_ban": {"enabled": True, "max_attacks": 5, "window_seconds": 60, "ban_seconds": 300},
    # The gateway (reverse proxy) sees every asset request, so it gets a much higher limit.
    "proxy_rate_limit": {"enabled": True, "max_requests": 300, "window_seconds": 60},
    "proxy": {
        "enabled": True,
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "backend_url": "http://127.0.0.1:5001",
        "mode": "block",              # block = refuse attacks | detect = log only, still forward
        "max_body_bytes": 131072,     # larger request bodies are rejected with 413
        "timeout_seconds": 10,
        "ml_on_obfuscated": True,
        "log_allowed": True,
    },
    "allowlist": [],          # IPs / CIDRs that skip every traffic control, e.g. ["10.0.0.0/8"]
    "blocklist": [],          # IPs / CIDRs that are always refused
    "trust_proxy_headers": False,   # only True if the app sits behind a proxy YOU control
}

# (action, category shown on the dashboard, rule id, HTTP status)
_ACTIONS = {
    "rate_limited": ("Rate Limited", "RATE-001", 429),
    "banned":       ("IP Banned",    "BAN-001",  403),
    "blocklisted":  ("IP Blocklist", "IP-001",   403),
}


class Decision(NamedTuple):
    action: str                 # allow | rate_limited | banned | blocklisted
    retry_after: int = 0        # seconds (0 when not applicable)

    @property
    def category(self): return _ACTIONS[self.action][0] if self.action in _ACTIONS else "None"
    @property
    def rule_id(self): return _ACTIONS[self.action][1] if self.action in _ACTIONS else None
    @property
    def http_status(self): return _ACTIONS[self.action][2] if self.action in _ACTIONS else 200


def _parse_networks(entries):
    nets = []
    for e in entries or []:
        try:
            nets.append(ipaddress.ip_network(str(e).strip(), strict=False))
        except ValueError:
            pass  # ignore typos instead of crashing the WAF
    return nets


def _in(nets, ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in n for n in nets)


class TrafficController:
    def __init__(self, config=None, config_path=CONFIG_PATH):
        self._lock = threading.Lock()
        self._path = Path(config_path) if config_path else None
        self._mtime = None
        self._requests = {}     # ip -> deque[timestamp]
        self._attacks = {}      # ip -> deque[timestamp]
        self._bans = {}         # ip -> expiry timestamp
        self._last_logged = {}  # (ip, action) -> timestamp
        self._calls = 0
        self.cfg = None
        self._apply(config if config is not None else self._load_file())

    # ---------- config ----------
    def _load_file(self):
        if not self._path or not self._path.exists():
            self._mtime = None
            return {}
        try:
            self._mtime = self._path.stat().st_mtime
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}  # bad JSON -> fall back to defaults rather than crash

    def _apply(self, user_cfg):
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        for key, val in (user_cfg or {}).items():
            if isinstance(val, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(val)
            elif key in cfg:
                cfg[key] = val
        self.cfg = cfg
        self._allow = _parse_networks(cfg["allowlist"])
        self._block = _parse_networks(cfg["blocklist"])

    def _maybe_reload(self):
        """Hot-reload waf_config.json when the file changes (checked cheaply per request)."""
        if not self._path:
            return
        try:
            mtime = self._path.stat().st_mtime if self._path.exists() else None
        except OSError:
            return
        if mtime != self._mtime:
            self._apply(self._load_file())

    @property
    def trust_proxy_headers(self):
        return bool(self.cfg["trust_proxy_headers"])

    # ---------- decisions ----------
    def check(self, ip, now=None, scope="default") -> Decision:
        now = time.time() if now is None else now
        with self._lock:
            self._maybe_reload()
            self._calls += 1
            if self._calls % 500 == 0:
                self._cleanup(now)

            if _in(self._allow, ip):
                return Decision("allow")
            if _in(self._block, ip):
                return Decision("blocklisted")

            expiry = self._bans.get(ip)
            if expiry:
                if expiry > now:
                    return Decision("banned", math.ceil(expiry - now))
                del self._bans[ip]

            rl = self.cfg["proxy_rate_limit" if scope == "proxy" else "rate_limit"]
            if rl["enabled"]:
                maxn, win = int(rl["max_requests"]), float(rl["window_seconds"])
                q = self._requests.setdefault((scope, ip), deque(maxlen=maxn + 1))
                while q and now - q[0] >= win:
                    q.popleft()
                q.append(now)
                if len(q) > maxn:
                    return Decision("rate_limited", max(1, math.ceil(win - (now - q[0]))))
            return Decision("allow")

    def record_attack(self, ip, now=None) -> bool:
        """Call after a request was blocked as an attack. True if this attack just triggered a ban."""
        now = time.time() if now is None else now
        with self._lock:
            ab = self.cfg["auto_ban"]
            if not ab["enabled"] or _in(self._allow, ip):
                return False
            maxn, win = int(ab["max_attacks"]), float(ab["window_seconds"])
            q = self._attacks.setdefault(ip, deque(maxlen=maxn))
            while q and now - q[0] >= win:
                q.popleft()
            q.append(now)
            if len(q) >= maxn and ip not in self._bans:
                self._bans[ip] = now + float(ab["ban_seconds"])
                q.clear()
                return True
            return False

    def should_log(self, ip, action, now=None, interval=10) -> bool:
        """Throttle DB rows: a flood of refused requests logs one row per IP per `interval` seconds."""
        now = time.time() if now is None else now
        with self._lock:
            last = self._last_logged.get((ip, action))
            if last is not None and now - last < interval:
                return False
            self._last_logged[(ip, action)] = now
            return True

    # ---------- admin helpers (used by the login feature later) ----------
    def active_bans(self, now=None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            return {ip: math.ceil(exp - now) for ip, exp in self._bans.items() if exp > now}

    def unban(self, ip) -> bool:
        with self._lock:
            self._attacks.pop(ip, None)
            for scope in ("default", "proxy"):
                self._requests.pop((scope, ip), None)
            return self._bans.pop(ip, None) is not None

    # ---------- housekeeping ----------
    def _cleanup(self, now):
        rl_win = max(float(self.cfg["rate_limit"]["window_seconds"]),
                     float(self.cfg["proxy_rate_limit"]["window_seconds"]))
        for key in [k for k, q in self._requests.items() if not q or now - q[-1] >= rl_win]:
            del self._requests[key]
        ab_win = float(self.cfg["auto_ban"]["window_seconds"])
        for ip in [i for i, q in self._attacks.items() if not q or now - q[-1] >= ab_win]:
            del self._attacks[ip]
        for ip in [i for i, e in self._bans.items() if e <= now]:
            del self._bans[ip]
        for k in [k for k, t in self._last_logged.items() if now - t > 3600]:
            del self._last_logged[k]


_controller = None


def get_controller() -> TrafficController:
    global _controller
    if _controller is None:
        _controller = TrafficController()
    return _controller
