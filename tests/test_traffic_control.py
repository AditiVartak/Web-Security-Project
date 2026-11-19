"""Unit tests for traffic_control (uses a fake clock, so they run instantly).
Run:  python tests/test_traffic_control.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.hybrid_waf.utils.traffic_control import TrafficController  # noqa: E402


def make(**over):
    cfg = {"rate_limit": {"max_requests": 5, "window_seconds": 60},
           "auto_ban": {"max_attacks": 3, "window_seconds": 60, "ban_seconds": 300}}
    cfg.update(over)
    return TrafficController(config=cfg, config_path=None)


def test_rate_limit_and_recovery():
    t = make()
    assert [t.check("1.1.1.1", now=i).action for i in range(5)] == ["allow"] * 5
    d = t.check("1.1.1.1", now=5)
    assert d.action == "rate_limited" and 1 <= d.retry_after <= 60 and d.http_status == 429
    assert t.check("2.2.2.2", now=5).action == "allow"          # other IPs unaffected
    assert t.check("1.1.1.1", now=200).action == "allow"        # window passed


def test_auto_ban_and_expiry():
    t = make()
    assert not t.record_attack("3.3.3.3", now=0)
    assert not t.record_attack("3.3.3.3", now=1)
    assert t.record_attack("3.3.3.3", now=2)                    # 3rd attack -> ban
    d = t.check("3.3.3.3", now=3)
    assert d.action == "banned" and d.http_status == 403 and d.retry_after > 290
    assert t.check("3.3.3.3", now=400).action == "allow"        # ban expired


def test_slow_attacks_do_not_ban():
    t = make()
    for i in range(10):
        assert not t.record_attack("4.4.4.4", now=i * 61)       # always outside the window


def test_allowlist_blocklist_cidr():
    t = make(allowlist=["10.0.0.0/8"], blocklist=["203.0.113.7", "198.51.100.0/24"])
    for i in range(50):
        assert t.check("10.1.2.3", now=i).action == "allow"     # never limited
    assert not t.record_attack("10.1.2.3", now=0)
    assert t.check("203.0.113.7").action == "blocklisted"
    assert t.check("198.51.100.99").action == "blocklisted"
    assert t.check("8.8.8.8").action == "allow"


def test_bad_config_values_ignored():
    t = make(allowlist=["not-an-ip", "10.0.0.1"])
    assert t.check("10.0.0.1").action == "allow"


def test_log_throttle():
    t = make()
    assert t.should_log("5.5.5.5", "rate_limited", now=0)
    assert not t.should_log("5.5.5.5", "rate_limited", now=5)
    assert t.should_log("5.5.5.5", "rate_limited", now=11)


def test_unban_and_active_bans():
    t = make()
    for i in range(3):
        t.record_attack("6.6.6.6", now=i)
    assert "6.6.6.6" in t.active_bans(now=3)
    assert t.unban("6.6.6.6") and t.check("6.6.6.6", now=4).action == "allow"


def test_disabled_features():
    t = make(rate_limit={"enabled": False}, auto_ban={"enabled": False})
    assert all(t.check("7.7.7.7", now=i).action == "allow" for i in range(100))
    assert not any(t.record_attack("7.7.7.7", now=i) for i in range(20))


def test_proxy_scope_has_its_own_limit():
    t = make(proxy_rate_limit={"max_requests": 3, "window_seconds": 60})
    assert [t.check("8.8.4.4", now=i, scope="proxy").action for i in range(4)] == ["allow"] * 3 + ["rate_limited"]
    assert t.check("8.8.4.4", now=5).action == "allow"          # default scope is independent
    for i in range(3):
        t.record_attack("8.8.4.4", now=i)
    assert t.check("8.8.4.4", now=6, scope="proxy").action == "banned"   # bans apply everywhere


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except AssertionError as e:
                fails += 1; print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
