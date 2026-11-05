"""Obfuscations applied to injection payloads.

These model concealment seen in malware and in prompt-injection research:
encoding, invisible characters, look-alike glyphs, and splitting a payload
across several strings so that no single string looks like an instruction.
"""

from __future__ import annotations

import base64
import random

ZWSP = "​"

# Latin -> Cyrillic/Greek look-alikes (subset of Unicode confusables).
HOMOGLYPHS = {
    "a": "а",
    "c": "с",
    "e": "е",
    "i": "і",
    "o": "о",
    "p": "р",
    "x": "х",
    "y": "у",
    "A": "Α",
    "B": "Β",
    "E": "Ε",
    "I": "Ι",
    "O": "Ο",
    "T": "Τ",
}

OBFUSCATIONS = ("none", "base64", "zero_width", "homoglyph", "split")


def obf_base64(text: str, rng: random.Random) -> str:
    blob = base64.b64encode(text.encode("utf-8")).decode("ascii")
    hint = rng.choice(
        [
            "reviewer_note_b64=",
            "cfg.notes (base64): ",
            "README_FOR_REVIEWERS.b64 ",
        ]
    )
    return hint + blob


def obf_zero_width(text: str, rng: random.Random) -> str:
    out = []
    for word in text.split(" "):
        if len(word) > 3:
            word = ZWSP.join(word)
        out.append(word)
    return " ".join(out)


def obf_homoglyph(text: str, rng: random.Random, rate: float = 0.6) -> str:
    return "".join(HOMOGLYPHS[ch] if ch in HOMOGLYPHS and rng.random() < rate else ch for ch in text)


def obf_split(text: str, rng: random.Random) -> str:
    """Split into short fragments, one per line (one string / literal each)."""
    words = text.split()
    chunks: list[str] = []
    cur: list[str] = []
    target = rng.randint(3, 5)
    for w in words:
        cur.append(w)
        if len(cur) >= target:
            chunks.append(" ".join(cur))
            cur = []
            target = rng.randint(3, 5)
    if cur:
        chunks.append(" ".join(cur))
    return "\n".join(chunks)


def apply(name: str, text: str, rng: random.Random) -> str:
    if name == "none":
        return text
    if name == "base64":
        return obf_base64(text, rng)
    if name == "zero_width":
        return obf_zero_width(text, rng)
    if name == "homoglyph":
        return obf_homoglyph(text, rng)
    if name == "split":
        return obf_split(text, rng)
    raise ValueError(f"unknown obfuscation {name!r}")
