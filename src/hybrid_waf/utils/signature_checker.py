"""Signature-based inspection (stage 1 of the hybrid WAF).

inspect(text)          -> full result dict (verdict, category, rule_id, ...)
check_signature(text)  -> just the verdict string, kept for backward compatibility
"""
from src.hybrid_waf.utils.normalizer import collapse, normalize
from src.hybrid_waf.utils.rules import RULES, OBFUSCATION_RULES


def _first_match(rules, text, exclude=()):
    for rule in rules:
        if rule.category not in exclude and rule.regex.search(text):
            return rule
    return None


def inspect(user_input: str, exclude_categories=()) -> dict:
    """Classify one input.

    verdict:
      malicious  - a rule matched the text exactly as sent
      obfuscated - text is encoded/hidden; decoded text may or may not hit a rule
                   (the ML model is still asked, see routes/proxy.py)
      valid      - nothing suspicious

    exclude_categories: rule categories to skip for this input (used for fields where a category
    makes no sense, e.g. SSRF in the browser's own Referer header).
    """
    raw = collapse(user_input)

    rule = _first_match(RULES, raw, exclude_categories)
    if rule:
        return {"verdict": "malicious", "category": rule.category, "rule_id": rule.id,
                "severity": rule.severity, "matched_on": "raw", "decoded": raw}

    decoded = normalize(user_input)
    obf = _first_match(OBFUSCATION_RULES, raw)

    if obf is None and decoded == raw:
        return {"verdict": "valid", "category": "None", "rule_id": None,
                "severity": None, "matched_on": None, "decoded": raw}

    # Encoded / transformed input: check what it says once decoded.
    hit = _first_match(RULES, decoded, exclude_categories)
    if hit:
        return {"verdict": "obfuscated", "category": hit.category, "rule_id": hit.id,
                "severity": hit.severity, "matched_on": "decoded", "decoded": decoded}
    rule = obf or OBFUSCATION_RULES[0]
    return {"verdict": "obfuscated", "category": "Obfuscated", "rule_id": rule.id,
            "severity": rule.severity, "matched_on": None, "decoded": decoded}


def check_signature(user_input: str) -> str:
    return inspect(user_input)["verdict"]
