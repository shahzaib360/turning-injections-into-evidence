"""Turn detector findings into report evidence and a verdict floor."""

from __future__ import annotations

from tie.defenses.detector import HIGH_THRESHOLD, DetectorResult

ORDER = {None: -1, "benign": 0, "suspicious": 1, "malicious": 2}


def max_verdict(a: str | None, b: str | None) -> str | None:
    return a if ORDER.get(a, -1) >= ORDER.get(b, -1) else b


def escalate(llm_verdict: str | None, det: DetectorResult) -> tuple[str | None, str | None]:
    """Return (final_verdict, reason). Never lowers the model's verdict."""
    if not det.flagged:
        return llm_verdict, None
    floor = "malicious" if det.max_score >= HIGH_THRESHOLD else "suspicious"
    final = max_verdict(llm_verdict, floor)
    reason = (
        f"artifact contains {len(det.manipulations)} span(s) of text addressed to an AI analyst "
        f"(max score {det.max_score:.1f}); treated as anti-analysis evidence"
    )
    return final, reason
