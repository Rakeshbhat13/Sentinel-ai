"""Text normalization — NFKC, zero-width strip, homoglyph fold, base64 decode.

Cheapest pre-processing step: clean the text before heuristic or LLM analysis.
"""

import base64
import re
import unicodedata

# Zero-width and invisible Unicode codepoints used to smuggle text
_INVISIBLE_RE = re.compile(
    "["
    "\u00ad"          # soft hyphen
    "\u034f"          # combining grapheme joiner
    "\u061c"          # Arabic letter mark
    "\u180e"          # Mongolian vowel separator
    "\u200b-\u200f"   # zero-width joiners / marks
    "\u2060-\u2064"   # invisible operators
    "\u206a-\u206f"   # deprecated formatting chars
    "\ufeff"          # BOM / zero-width no-break space
    "\ufff9-\ufffb"   # interlinear annotations
    "]+"
)

# BiDi override characters used to visually reorder text
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]+")

# Common homoglyph mappings (Cyrillic/Greek → Latin)
_HOMOGLYPHS: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)

# Inline base64 segments (e.g., "base64: aWdub3JlIHByZXZpb3Vz...")
_B64_INLINE_RE = re.compile(
    r"(?:base64[:\s]+)([A-Za-z0-9+/]{20,}={0,2})", re.I
)


def normalize_text(text: str) -> str:
    """Full normalization pipeline: strip invisible chars, fold homoglyphs,
    NFKC normalize, decode inline base64 segments."""
    # 1. Strip zero-width / invisible characters
    text = _INVISIBLE_RE.sub("", text)

    # 2. Strip BiDi overrides
    text = _BIDI_RE.sub("", text)

    # 3. NFKC normalization (canonical + compatibility decomposition)
    text = unicodedata.normalize("NFKC", text)

    # 4. Fold homoglyphs to Latin
    text = text.translate(_HOMOGLYPH_TABLE)

    # 5. Decode inline base64 segments, appending decoded text in brackets
    def _decode_b64(m: re.Match) -> str:
        try:
            decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8", errors="ignore")
            return f"{m.group(0)} [decoded: {decoded}]"
        except Exception:
            return m.group(0)

    text = _B64_INLINE_RE.sub(_decode_b64, text)

    return text
