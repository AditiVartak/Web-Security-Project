"""Inspect a whole HTTP request (path, query, headers, cookies, body), not just one text box.

Each part is scanned separately with the same engine as /check_request, so a finding can say
WHERE the attack was (e.g. "header:User-Agent"). Pure function: no Flask, easy to unit test.
"""
from src.hybrid_waf.utils.signature_checker import inspect

CHUNK = 8000   # the engine looks at <= 10,000 chars at a time ...
STEP = 7000    # ... so long bodies are scanned in overlapping windows (stops "pad then attack" evasion)

# Headers that are noisy, standardized, or contain opaque tokens: not worth scanning.
SKIP_HEADERS = {
    "host", "connection", "content-length", "content-type", "accept", "accept-encoding",
    "accept-language", "accept-charset", "authorization", "cache-control", "pragma",
    "upgrade-insecure-requests", "if-none-match", "if-modified-since", "te", "expect",
    "keep-alive", "dnt", "priority", "origin-agent-cluster",
}
MAX_HEADER_CHARS = 2000

# Rule categories that make no sense for a given field. Browsers put their OWN address in Referer
# and Origin (e.g. http://127.0.0.1:8080/ while testing locally), which looks like an SSRF target
# but is not one: SSRF is about URLs sent as DATA that the server might fetch.
# Everything else (XSS, SQLi, Log4Shell ...) is still checked in these headers.
LOCATION_EXCLUSIONS = {
    "header:referer": ("SSRF",),
    "header:origin": ("SSRF",),
}


def _windows(text: str):
    if len(text) <= CHUNK:
        yield text
        return
    for start in range(0, len(text), STEP):
        yield text[start:start + CHUNK]
        if start + CHUNK >= len(text):
            break


def _scan(location: str, text: str, findings: list) -> bool:
    """Scan one value. Returns True as soon as a signature rule matches the raw text."""
    exclude = LOCATION_EXCLUSIONS.get(location.lower(), ())
    for part in _windows(text):
        r = inspect(part, exclude_categories=exclude)
        if r["verdict"] == "valid":
            continue
        findings.append({**r, "location": location, "value": part})
        if r["verdict"] == "malicious":
            return True
    return False


def inspect_request(*, method, path, query, headers, body=b"", ml_predict=None) -> dict:
    """Return the decision for one request.

    action:      allow | block
    status:      valid | obfuscated | malicious      (what the engine thinks of the traffic)
    detected_by: none | signature | signature(decoded) | ml
    ml_predict:  optional callable(path, query, body_text) -> bool, asked only for encoded input
                 that no rule recognised once decoded.
    """
    findings = []
    body_text = body.decode("utf-8", errors="replace") if body else ""

    targets = [("path", path or ""), ("query", query or "")]
    for name, value in headers.items():
        lname = name.lower()
        if lname == "cookie":
            targets.append(("cookie", value[:MAX_HEADER_CHARS]))
        elif lname not in SKIP_HEADERS and not lname.startswith("sec-"):
            targets.append((f"header:{name}", value[:MAX_HEADER_CHARS]))
    targets.append(("body", body_text))

    for location, text in targets:
        if text and _scan(location, text, findings):
            f = findings[-1]
            return _result("block", "malicious", f, "signature")

    # Encoded input: did the decoded text reveal a known attack?
    for f in findings:
        if f["matched_on"] == "decoded":
            return _result("block", "obfuscated", f, "signature(decoded)")

    if findings:  # encoded but not recognised -> second opinion from the ML model
        if ml_predict is not None:
            try:
                if ml_predict(path or "", query or "", body_text):
                    return _result("block", "obfuscated", findings[0], "ml")
            except Exception as exc:   # never let an ML hiccup take the site down
                print(f"[WAFinity] ML check failed, allowing request: {exc!r}")
        return _result("allow", "obfuscated", findings[0], "ml" if ml_predict else "none")

    return {"action": "allow", "status": "valid", "category": "None", "rule_id": None,
            "location": None, "value": None, "detected_by": "none"}


def _result(action, status, finding, detected_by):
    return {"action": action, "status": status,
            "category": finding["category"], "rule_id": finding["rule_id"],
            "location": finding["location"], "value": finding["value"],
            "detected_by": detected_by}
