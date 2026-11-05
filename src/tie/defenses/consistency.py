"""Consistency checks across models and across views.

* **Cross-model**: different model families rarely share the same quirks, so
  an injection that flips one model often fails on another. Any disagreement
  between a "benign" verdict and a flag, or an abort next to a completed
  analysis, is itself a signal and is escalated to ``suspicious``.
* **Counterfactual view**: run the same model on the raw artifact and on the
  quarantined view. Legitimate text has no reason to change the verdict when
  it is removed; if the verdict or the abort status changes, the removed text
  was acting as an instruction. Disagreement is escalated, and the
  quarantined view's verdict is kept when it is the more severe one.
"""

from __future__ import annotations

from tie.defenses.evidence import ORDER, max_verdict
from tie.schema import TriageReport


def _flagged(r: TriageReport) -> bool:
    return r.status == "completed" and r.verdict in ("malicious", "suspicious")


def cross_model(reports: list[TriageReport]) -> tuple[str | None, bool]:
    """Return (combined_verdict, disagreement)."""
    statuses = {r.status for r in reports}
    flags = {_flagged(r) for r in reports if r.status == "completed"}
    disagreement = len(flags) > 1 or len(statuses) > 1
    verdict = None
    for r in reports:
        if r.status == "completed":
            verdict = max_verdict(verdict, r.verdict)
    if disagreement:
        verdict = max_verdict(verdict, "suspicious")
    return verdict, disagreement


def counterfactual(raw: TriageReport, view: TriageReport) -> tuple[str | None, bool]:
    """Compare a raw-view run with a quarantined-view run of the same model.

    ``view.llm_verdict`` (before any detector escalation) is used for the
    comparison so the check measures the model, not the detector.
    """
    raw_v = raw.verdict if raw.status == "completed" else None
    view_v = view.llm_verdict if view.llm_verdict is not None else (view.verdict if view.status == "completed" else None)
    changed = (raw.status != view.status and view.llm_verdict is None) or (
        (raw_v in ("malicious", "suspicious")) != (view_v in ("malicious", "suspicious"))
    ) or (raw_v is None) != (view_v is None)
    final = view.verdict if view.status == "completed" else None
    final = max_verdict(final, view_v)
    if changed:
        final = max_verdict(final, "suspicious")
        if ORDER.get(view_v, -1) == 2 or ORDER.get(raw_v, -1) == 2:
            final = "malicious"
    return final, changed
