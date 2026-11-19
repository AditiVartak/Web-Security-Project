"""Detection rules. Each rule has an id, a category, a severity and one regex.

To add a rule: append a Rule(...) to RULES. Keep patterns bounded ({0,80}, not .*)
so a malicious input can't make the regex engine run for ages (ReDoS).
"""
import re
from dataclasses import dataclass

_I = re.IGNORECASE


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str          # low | medium | high | critical
    description: str
    regex: re.Pattern


def _r(rid, cat, sev, desc, pattern, flags=_I):
    return Rule(rid, cat, sev, desc, re.compile(pattern, flags))


RULES = [
    # ---------------- SQL injection ----------------
    _r("SQLI-001", "SQLi", "critical", "UNION SELECT",
       r"\bunion\b\s*(?:all\s+|distinct\s+)?\bselect\b"),
    _r("SQLI-002", "SQLi", "high", "Boolean tautology (' OR '1'='1, OR 1=1)",
       r"\b(?:or|and)\b\s+['\"]?(\w{1,20})['\"]?\s*(?:=|like)\s*['\"]?\1\b"),
    _r("SQLI-003", "SQLi", "critical", "Stacked / destructive statement",
       r";\s*(?:drop|delete|insert|update|alter|truncate|create|exec|shutdown)\b|\bdrop\s+(?:table|database)\b"),
    _r("SQLI-004", "SQLi", "high", "Time-based blind SQLi",
       r"\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    _r("SQLI-005", "SQLi", "high", "SELECT probing (select *, @@version, ... from users)",
       r"\bselect\s+(?:\*|@@\w+|null\b|version\s*\(|user\s*\(|database\s*\(|load_file\s*\(|distinct\b|top\s+\d)"
       r"|\bselect\b.{0,80}\bfrom\b\s+(?:users?|information_schema|mysql|sysobjects|dual|accounts?|admins?)\b"),
    _r("SQLI-006", "SQLi", "high", "Quote followed by SQL comment (admin'--)",
       r"['\"]\s*(?:--(?=\s|$|&|;|\)|-)|#(?=\s|$|&|;)|/\*)|;\s*--"),
    _r("SQLI-007", "SQLi", "medium", "ORDER BY column probing",
       r"\border\s+by\s+\d+\s*(?:--|#|/\*|;|$)"),
    _r("SQLI-008", "SQLi", "high", "SQL functions used for data extraction",
       r"\b(?:extractvalue|updatexml|load_file|xp_cmdshell|information_schema)\b|\binto\s+(?:out|dump)file\b"),
    _r("SQLI-009", "SQLi", "medium", "DML statement with SQL structure",
       r"\binsert\s+into\s+\w+|\bdelete\s+from\s+\w+\s*(?:where\b|;|--|$)|\bupdate\s+\w+\s+set\s+\w+\s*="),

    # ---------------- Cross-site scripting ----------------
    _r("XSS-001", "XSS", "critical", "<script> tag", r"<\s*/?\s*script\b"),
    _r("XSS-002", "XSS", "high", "Inline event handler",
       r"\bon(?:error|load|click|dblclick|mouseover|mouseout|mouseenter|focus|blur|toggle|"
       r"keydown|keyup|keypress|submit|change|input|animationstart|pointerdown|begin)\s*="),
    _r("XSS-003", "XSS", "high", "javascript:/vbscript:/data:text/html URI",
       r"\b(?:javascript|vbscript)\s*:|data\s*:\s*text/html"),
    _r("XSS-004", "XSS", "high", "JavaScript sink / call",
       r"\b(?:alert|prompt|confirm|eval)\s*\(|document\s*\.\s*(?:cookie|write|location|domain)"
       r"|\bwindow\s*\.\s*location|\bString\s*\.\s*fromCharCode|\b(?:inner|outer)HTML\s*="
       r"|\bset(?:timeout|interval)\s*\(|\bfetch\s*\(|\bxhr\s*\.\s*open\s*\(|constructor\s*\.\s*constructor"),
    _r("XSS-005", "XSS", "high", "Script-capable HTML tag",
       r"<\s*(?:img|svg|body|video|audio|marquee|math|source|track)\b"),

    # ---------------- HTML injection ----------------
    _r("HTML-001", "HTML Injection", "medium", "Raw HTML tag in input",
       r"</?(?:div|span|p|h[1-6]|a|form|input|button|table|tr|td|textarea|select|option|label|"
       r"fieldset|iframe|embed|object|style|link|meta|base|html|head|font|center|br|hr)\b"),

    # ---------------- SSRF ----------------
    _r("SSRF-001", "SSRF", "high", "Dangerous URL scheme",
       r"\b(?:file|gopher|dict|ftp|sftp|tftp|ldap|jar|netdoc)://"),
    _r("SSRF-002", "SSRF", "high", "URL pointing at loopback / private / metadata host",
       r"\bhttps?://(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1?\]|0x7f[0-9a-f]*|"
       r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
       r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|"
       r"metadata\.google\.internal|kubernetes\.default\.svc)"),
    _r("SSRF-003", "SSRF", "critical", "Cloud metadata endpoint", r"169\.254\.169\.254|metadata\.google\.internal"),

    # ---------------- Path traversal / LFI ----------------
    _r("PATH-001", "Path Traversal", "high", "Directory traversal sequence", r"\.\.[/\\]|\.\.;/"),
    _r("PATH-002", "Path Traversal", "high", "Sensitive system file",
       r"/etc/(?:passwd|shadow|hosts|group)\b|[a-z]:[/\\]windows\b|\bboot\.ini\b|\bwin\.ini\b|/proc/self/|"
       r"\bwp-config\.php\b|[/\\]\.(?:env|git|ssh|htaccess|htpasswd)\b"),

    # ---------------- OS command injection ----------------
    _r("CMD-001", "Command Injection", "critical", "Shell metacharacter followed by a command",
       r"(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|"
       r"cmd|powershell|ping|nslookup|echo|rm|chmod|chown|ifconfig|ipconfig|netstat|kill|touch|mkdir|tftp)\b"),
    _r("CMD-002", "Command Injection", "critical", "Shell invocation",
       r"/bin/(?:ba)?sh\b|\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-|\bbash\s+-[ci]\b"),

    # ---------------- Log4Shell / JNDI ----------------
    _r("LOG4J-001", "Log4Shell", "critical", "JNDI lookup (incl. nested obfuscation)",
       r"\$\{\s*(?:jndi|\$\{|lower:|upper:|env:|sys:|java:|ctx:)"),

    # ---------------- Server-side template injection ----------------
    _r("SSTI-001", "SSTI", "high", "Template expression",
       r"\{\{.{0,60}?(?:\d+\s*[*+\-/]\s*\d+|config|self|request|lipsum|cycler|joiner|namespace|__)\w*.{0,60}?\}\}"
       r"|\{%.{1,80}?%\}|\$\{\s*\d+\s*[*+\-/]\s*\d+\s*\}|#\{\s*\d+\s*[*+\-/]\s*\d+\s*\}|<%=?.{1,80}?%>"),
    _r("SSTI-002", "SSTI", "high", "Python object-graph escape",
       r"__(?:class|mro|subclasses|globals|builtins|import)__"),

    # ---------------- NoSQL injection ----------------
    _r("NOSQL-001", "NoSQLi", "high", "MongoDB operator injection",
       r"[\"']?\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|or|and|nor|expr)[\"']?\s*:"
       r"|\[\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists)\]\s*="),
    _r("NOSQL-002", "NoSQLi", "medium", "JS-style tautology (|| '1'=='1')",
       r"\|\|\s*['\"]?\w{1,20}['\"]?\s*==\s*['\"]?\w{1,20}"),

    # ---------------- XXE ----------------
    _r("XXE-001", "XXE", "critical", "XML DOCTYPE/ENTITY declaration",
       r"<!\s*(?:DOCTYPE|ENTITY)\b|\bSYSTEM\s+[\"'](?:file|http|ftp|php|expect)"),

    # ---------------- LDAP injection ----------------
    _r("LDAP-001", "LDAP Injection", "high", "LDAP filter injection",
       r"[)(]\s*[|&!]\s*\(\s*\w{1,20}\s*=|\*\s*\)\s*\(\s*\w{1,20}\s*=\s*\*"),
]

# Most specific categories first, so e.g. "${jndi:ldap://x}" is reported as Log4Shell, not SSRF.
_PRIORITY = ["Log4Shell", "XXE", "SSTI", "Command Injection", "SQLi", "XSS", "NoSQLi",
             "LDAP Injection", "SSRF", "Path Traversal", "HTML Injection"]
RULES.sort(key=lambda r: _PRIORITY.index(r.category))   # stable: keeps order inside a category

# Things that look encoded/hidden. Not an attack by themselves, so they go to the ML model.
OBFUSCATION_RULES = [
    _r("OBF-001", "Obfuscated", "low", "URL percent-encoding", r"(?:%[0-9A-Fa-f]{2})+"),
    _r("OBF-002", "Obfuscated", "low", "Hex escape sequence", r"(?:\\x[0-9A-Fa-f]{2})+"),
    _r("OBF-003", "Obfuscated", "low", "Unicode escape sequence", r"(?:\\u[0-9A-Fa-f]{4})+"),
    _r("OBF-004", "Obfuscated", "low", "HTML entity encoding", r"&(?:#x?[0-9a-fA-F]+|lt|gt|quot|amp);"),
    _r("OBF-005", "Obfuscated", "low", "SQL string-building functions",
       r"\b(?:char|concat|substr|substring)\s*\(|\bcase\s+when\b"),
    _r("OBF-006", "Obfuscated", "low", "Encoding/decoding helper names",
       r"\b(?:base64_decode|base64_encode|fromCharCode|charCodeAt|decodeURIComponent|encodeURIComponent|hexToInt)\b"),
]
