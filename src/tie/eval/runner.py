"""Run pipelines x defenses over a benchmark split, with resumable JSONL output."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from tie.bench import binaries
from tie.defenses import detector as det_mod
from tie.defenses import quarantine
from tie.llm.base import ChatModel
from tie.pipelines.common import DEFENSES
from tie.pipelines.re_agent import REAgent
from tie.pipelines.re_backends import R2Backend
from tie.pipelines.single_shot import SingleShotTriage
from tie.schema import Sample, TriageReport

PIPELINE_FOR = {
    "strings": "strings_triage",
    "package": "pkg_scanner",
    "email": "email_triage",
    "decompiled": "ghidra_agent",
    "binary": "r2_agent",
}


class Runner:
    def __init__(self, model: ChatModel, build_dir: str | Path = "build/binaries", budget_chars: int = 6000):
        self.model = model
        self.build_dir = Path(build_dir)
        self.single = {
            k: SingleShotTriage(model, name=PIPELINE_FOR[k], budget_chars=budget_chars) for k in ("strings", "package", "email")
        }
        self.ghidra_agent = REAgent(model, name="ghidra_agent")
        self.r2_agent = REAgent(model, name="r2_agent")

    def run_one(self, sample: Sample, defense: str) -> TriageReport:
        cfg = DEFENSES[defense]
        if sample.artifact_type in self.single:
            return self.single[sample.artifact_type].run(sample, cfg)
        if sample.artifact_type == "decompiled":
            return self.ghidra_agent.run(sample, cfg)
        if sample.artifact_type == "binary":
            elf = binaries.build(sample.binary_source, self.build_dir)
            backend = R2Backend(str(elf))
            try:
                det = facts = None
                if cfg.quarantine:
                    strings = backend.list_strings()
                    det = det_mod.analyze_files({"strings.txt": strings})
                    facts = quarantine.extract_facts({"strings.txt": strings, "imports.txt": backend.list_imports()}, det)
                return self.r2_agent.run_with_backend(sample, backend, cfg, det=det, facts=facts)
            finally:
                backend.close()
        raise ValueError(f"no pipeline for artifact type {sample.artifact_type!r}")


def run_split(
    samples: list[Sample],
    model: ChatModel,
    defenses: list[str],
    out_path: str | Path,
    build_dir: str | Path = "build/binaries",
    log=sys.stderr,
) -> int:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done: set[tuple[str, str]] = set()
    if out_path.exists():
        for line in out_path.read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                done.add((d["sample_id"], d["defense"]))
    runner = Runner(model, build_dir=build_dir)
    todo = [(s, d) for d in defenses for s in samples if (s.id, d) not in done]
    t_start = time.time()
    n = 0
    with out_path.open("a", encoding="utf-8") as fh:
        for i, (s, d) in enumerate(todo, 1):
            try:
                rep = runner.run_one(s, d)
            except Exception as e:  # keep going; record the error
                rep = TriageReport(
                    sample_id=s.id, pipeline=PIPELINE_FOR.get(s.artifact_type, "?"), model=model.name, defense=d,
                    status="error", abort_reason=f"exception: {type(e).__name__}: {e}",
                )
            fh.write(json.dumps(rep.to_dict(), ensure_ascii=False) + "\n")
            fh.flush()
            n += 1
            el = time.time() - t_start
            eta = el / i * (len(todo) - i)
            print(
                f"[{model.name}] {i}/{len(todo)} {d:15s} {s.id[:60]:60s} -> {rep.status}/{rep.verdict} "
                f"({rep.elapsed_s:.1f}s, eta {eta / 60:.0f}m)",
                file=log,
                flush=True,
            )
    return n
