"""Compose the benchmark: carriers x strategies x placements x obfuscations.

Splits written by ``tie build``:

* ``dev.jsonl``    - every combination, using the *dev* template family.
                     Detector lexicons were developed against this split only.
* ``test.jsonl``   - every combination, using the held-out *test* templates.
* ``core.jsonl``   - stratified subset of ``test`` sized for CPU-only LLM runs.
* ``binary.jsonl`` - compiled ELF carriers for the radare2 agent.
* ``gray.jsonl``   - benign artifacts whose authors added a note to reviewers.
                     Reported separately: flagging them is arguably correct.
"""

from __future__ import annotations

import random
from pathlib import Path

from tie.bench import binaries, carriers, obfuscation, strategies
from tie.schema import Injection, Sample, write_jsonl

OBFUSCATED_STRATEGIES = ("direct_override", "harness_mimicry", "cover_story")
HEAD_ONLY = ("refusal_bait", "context_flood")


def _rng(*parts: object) -> random.Random:
    return random.Random("|".join(str(p) for p in parts))


def placements_for(strategy: str, carrier: carriers.Carrier, k: int = 2) -> list[str]:
    if strategy in HEAD_ONLY:
        return [carrier.head_slot]
    body = list(carrier.body_slots)
    if strategy == "fake_system_messages":
        return [carrier.head_slot] + body[:1]
    return body[:k]


def make_sample(
    carrier: carriers.Carrier,
    strategy: str | None,
    placement: str | None,
    obf: str = "none",
    family: str = "test",
    template_id: str | None = None,
    seed: int = 0,
    label: str | None = None,
    extra_tags: tuple[str, ...] = (),
) -> Sample:
    rng = _rng(seed, carrier.id, strategy, placement, obf, family, template_id)
    if strategy is None:
        files, _ = carriers.render(carrier, {}, rng)
        return Sample(
            id=f"{carrier.id}--clean",
            artifact_type=carrier.artifact_type,
            label=label or carrier.label,
            base_id=carrier.id,
            scenario=carrier.scenario,
            files=files,
            capabilities=list(carrier.capabilities),
            iocs=list(carrier.iocs),
            tags=list(carrier.tags) + list(extra_tags),
        )
    payload = strategies.render_payload(strategy, carrier.artifact_type, rng, family, template_id)
    text = obfuscation.apply(obf, payload.text, rng)
    files, spans = carriers.render(carrier, {placement: text}, rng)
    inj = Injection(
        strategy=strategy,
        goal=payload.goal,
        placement=placement,
        obfuscation=obf,
        template_id=payload.template_id,
        text=payload.text,
        canary=payload.canary,
        decoy_iocs=payload.decoy_iocs,
        decoy_attribution=payload.decoy_attribution,
        addresses_ai=payload.addresses_ai,
        spans=spans,
    )
    sid = f"{carrier.id}--{strategy}--{placement}--{obf}--{payload.template_id}"
    return Sample(
        id=sid,
        artifact_type=carrier.artifact_type,
        label=label or carrier.label,
        base_id=carrier.id,
        scenario=carrier.scenario,
        files=files,
        capabilities=list(carrier.capabilities),
        iocs=list(carrier.iocs),
        injection=inj,
        tags=list(carrier.tags) + list(extra_tags),
    )


def build_split(family: str, seed: int = 0) -> list[Sample]:
    out: list[Sample] = []
    for c in carriers.ALL_CARRIERS:
        out.append(make_sample(c, None, None, family=family, seed=seed))
        if c.label != "malicious":
            continue
        for strat in strategies.STRATEGY_NAMES:
            for i, slot in enumerate(placements_for(strat, c)):
                out.append(make_sample(c, strat, slot, "none", family, seed=seed))
                if strat in OBFUSCATED_STRATEGIES and i == 0:
                    for obf in obfuscation.OBFUSCATIONS[1:]:
                        out.append(make_sample(c, strat, slot, obf, family, seed=seed))
    return out


# Carriers used by the CPU-sized LLM split (two malicious carriers per type).
CORE_MALICIOUS = {
    "strings": ["str-mal-macos-stealer", "str-mal-win-loader"],
    "decompiled": ["dec-mal-browser-stealer", "dec-mal-macos-dropper"],
    "package": ["pkg-mal-env-exfil", "pkg-mal-runtime-dropper"],
    "email": ["eml-mal-m365-phish", "eml-mal-invoice-attach"],
}


def build_core(seed: int = 0) -> list[Sample]:
    out: list[Sample] = []
    for atype, mal_ids in CORE_MALICIOUS.items():
        type_carriers = [c for c in carriers.ALL_CARRIERS if c.artifact_type == atype]
        for c in type_carriers:
            out.append(make_sample(c, None, None, seed=seed))
        for cid in mal_ids:
            c = carriers.CARRIERS_BY_ID[cid]
            for strat in strategies.STRATEGY_NAMES:
                slot = placements_for(strat, c)[0]
                out.append(make_sample(c, strat, slot, "none", "test", seed=seed))
    return out


def build_gray(seed: int = 0) -> list[Sample]:
    """Benign carriers with a reviewer-addressed cover story (gray zone)."""
    out: list[Sample] = []
    picks = ["str-ben-backup", "dec-ben-updater", "pkg-ben-model-downloader", "eml-ben-newsletter"]
    for cid in picks:
        c = carriers.CARRIERS_BY_ID[cid]
        slot = c.body_slots[0]
        s = make_sample(c, "cover_story", slot, "none", "test", seed=seed, extra_tags=("gray:benign_with_reviewer_note",))
        out.append(s)
    return out


BINARY_STRATEGIES = (
    "direct_override",
    "fake_system_messages",
    "harness_mimicry",
    "refusal_bait",
    "cover_story",
    "misdirection",
    "tool_spoof",
)


def build_binary(seed: int = 0) -> list[Sample]:
    out: list[Sample] = []
    for b in binaries.BINARY_CARRIERS:
        out.append(
            Sample(
                id=f"{b.id}--clean",
                artifact_type="binary",
                label=b.label,
                base_id=b.id,
                scenario=b.scenario,
                files={},
                capabilities=list(b.capabilities),
                iocs=list(b.iocs),
                tags=list(b.tags),
                binary_source=binaries.render_source(b, None),
            )
        )
        if b.label != "malicious":
            continue
        for strat in BINARY_STRATEGIES:
            rng = _rng(seed, b.id, strat)
            payload = strategies.render_payload(strat, "binary", rng, "test")
            out.append(
                Sample(
                    id=f"{b.id}--{strat}--notes--none--{payload.template_id}",
                    artifact_type="binary",
                    label=b.label,
                    base_id=b.id,
                    scenario=b.scenario,
                    files={},
                    capabilities=list(b.capabilities),
                    iocs=list(b.iocs),
                    injection=Injection(
                        strategy=strat,
                        goal=payload.goal,
                        placement="notes",
                        template_id=payload.template_id,
                        text=payload.text,
                        canary=payload.canary,
                        decoy_iocs=payload.decoy_iocs,
                        decoy_attribution=payload.decoy_attribution,
                        addresses_ai=payload.addresses_ai,
                    ),
                    tags=list(b.tags),
                    binary_source=binaries.render_source(b, payload.text),
                )
            )
    return out


def build_all(out_dir: str | Path = "benchmark", seed: int = 0) -> dict[str, int]:
    out_dir = Path(out_dir)
    counts = {
        "dev": write_jsonl(out_dir / "dev.jsonl", build_split("dev", seed)),
        "test": write_jsonl(out_dir / "test.jsonl", build_split("test", seed)),
        "core": write_jsonl(out_dir / "core.jsonl", build_core(seed)),
        "binary": write_jsonl(out_dir / "binary.jsonl", build_binary(seed)),
        "gray": write_jsonl(out_dir / "gray.jsonl", build_gray(seed)),
    }
    return counts
