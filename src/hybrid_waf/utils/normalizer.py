"""Input normalizer: undo common encoding tricks so rules see what the attacker really sent."""
import html
import re
import unicodedata
from urllib.parse import unquote

MAX_INPUT_CHARS = 10_000   # cap work per request (also limits regex backtracking cost)
MAX_DECODE_ROUNDS = 3      # catches double/triple URL-encoding

_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNI_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS = re.compile(r"\s+")


def collapse(text: str) -> str:
    """Trim and collapse all whitespace runs to a single space (no decoding)."""
    return _WS.sub(" ", (text or "")[:MAX_INPUT_CHARS]).strip()


def normalize(text: str) -> str:
    """Return a decoded, canonical version of the input.

    Steps (repeated up to MAX_DECODE_ROUNDS until the text stops changing):
      URL-decode (%27 -> '), \\xNN and \\uNNNN escapes, HTML entities (&lt; -> <),
      Unicode NFKC (fullwidth chars -> ASCII), null-byte removal,
      SQL inline comments (UN/**/ION -> UN ION is NOT merged; /**/ becomes a space),
      whitespace collapsing.
    """
    t = (text or "")[:MAX_INPUT_CHARS]
    for _ in range(MAX_DECODE_ROUNDS):
        prev = t
        t = unquote(t)  # note: '+' is left alone on purpose ('a'+'b' is JS concatenation)
        t = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), t)
        t = _UNI_ESC.sub(lambda m: chr(int(m.group(1), 16)), t)
        t = html.unescape(t)
        t = unicodedata.normalize("NFKC", t)
        t = t.replace("\x00", "")
        t = _SQL_COMMENT.sub(" ", t)
        if t == prev:
            break
    return _WS.sub(" ", t).strip()
