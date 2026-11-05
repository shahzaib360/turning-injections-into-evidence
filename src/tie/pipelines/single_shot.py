"""Single-shot LLM triage (strings dumps, packages, emails, decompiled code).

This mirrors the common open-source pattern: read the artifact (truncated to an
input budget), put it in a prompt, ask for a JSON verdict, parse leniently.
"""

from __future__ import annotations

import time

from tie.defenses import detector as det_mod
from tie.defenses import evidence, quarantine
from tie.llm.base import ChatModel
from tie.pipelines import common
from tie.schema import Sample, TriageReport


def raw_view(sample: Sample) -> str:
    return sample.text()


class SingleShotTriage:
    def __init__(self, model: ChatModel, name: str = "single_shot", budget_chars: int = 6000, max_tokens: int = 220):
        self.model = model
        self.name = name
        self.budget = budget_chars
        self.max_tokens = max_tokens

    def build_messages(self, sample: Sample, cfg: common.DefenseConfig, nonce: str | None = None):
        nonce = nonce or common.new_nonce()
        det = None
        facts = None
        if cfg.quarantine:
            det = det_mod.analyze_sample(sample)
            view = quarantine.build_view(sample.files, det, self.budget)
            facts = quarantine.extract_facts(sample.files, det)
        else:
            view = common.truncate_head(raw_view(sample), self.budget)
        messages = [
            {"role": "system", "content": common.system_prompt(sample.artifact_type, cfg, nonce)},
            {"role": "user", "content": common.wrap_artifact(view, sample.artifact_type, cfg, nonce, facts)},
        ]
        return messages, det

    def run(self, sample: Sample, cfg: common.DefenseConfig) -> TriageReport:
        t0 = time.time()
        messages, det = self.build_messages(sample, cfg)
        res = self.model.chat(messages, max_tokens=self.max_tokens, temperature=0.0)
        parsed = common.parse_report(res.text)
        rep = TriageReport(
            sample_id=sample.id,
            pipeline=self.name,
            model=self.model.name,
            defense=cfg.name,
            verdict=parsed["verdict"],
            status=parsed["status"],
            abort_reason=parsed["abort_reason"],
            confidence=parsed["confidence"],
            capabilities=parsed["capabilities"],
            iocs=parsed["iocs"],
            attribution=parsed["attribution"],
            summary=parsed["summary"],
            raw_output=res.text,
            llm_verdict=parsed["verdict"],
            prompt_tokens=res.prompt_tokens,
            completion_tokens=res.completion_tokens,
        )
        if cfg.escalate:
            if det is None:
                det = det_mod.analyze_sample(sample)
            apply_escalation(rep, det)
        rep.elapsed_s = time.time() - t0
        return rep


def apply_escalation(rep: TriageReport, det) -> None:
    rep.evidence = det.evidence()
    final, reason = evidence.escalate(rep.llm_verdict if rep.status == "completed" else None, det)
    if reason:
        if rep.status != "completed":
            rep.abort_reason = f"llm_{rep.abort_reason}_escalated"
            rep.status = "completed"
        rep.verdict = final
        rep.summary = (rep.summary + " | " if rep.summary else "") + reason
