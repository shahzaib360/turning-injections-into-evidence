"""Normalisation that undoes common concealment before scoring text.

Returns the normalised text plus the concealment techniques that were seen,
because concealment is itself evidence.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Inverse confusables for common Cyrillic / Greek look-alikes of Latin letters.
CONFUSABLES = {
    "а": "a", "с": "c", "е": "e", "і": "i", "о": "o", "р": "p",
    "х": "x", "у": "y", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i", "ρ": "p",
}
_CONF_TABLE = {ord(k): v for k, v in CONFUSABLES.items()}

_B64 = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){16,})(?![0-9a-fA-F])")
_LATIN = re.compile(r"[A-Za-z]")


def _mixed_script(word: str) -> bool:
    has_latin = bool(_LATIN.search(word))
    has_conf = any(ch in CONFUSABLES for ch in word)
    return has_latin and has_conf


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for ch in s if ch.isprintable() or ch in "\n\t")
    return good / len(s)


def decode_blobs(text: str) -> list[tuple[str, str]]:
    """Return (encoding, decoded_text) for base64/hex blobs that decode to prose."""
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(dec) >= 12 and _printable_ratio(dec) > 0.95 and len(re.findall(r"[A-Za-z]{3,}", dec)) >= 3:
            out.append(("base64", dec))
    for m in _HEX.finditer(text):
        try:
            dec = bytes.fromhex(m.group(1)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.95 and len(re.findall(r"[A-Za-z]{3,}", dec)) >= 3:
            out.append(("hex", dec))
    return out


def normalize(text: str) -> tuple[str, set[str]]:
    flags: set[str] = set()
    if any(ord(ch) in ZERO_WIDTH for ch in text):
        flags.add("zero_width")
        text = text.translate(ZERO_WIDTH)
    words = text.split()
    if any(_mixed_script(w) for w in words):
        flags.add("homoglyph")
    if any(ord(ch) in _CONF_TABLE for ch in text):
        text = text.translate(_CONF_TABLE)
    text = unicodedata.normalize("NFKC", text)
    return text, flags
