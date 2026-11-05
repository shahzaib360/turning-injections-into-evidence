"""Command-line interface: ``tie build | detect | run | report``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_build(a):
    from tie.bench.build import build_all

    counts = build_all(a.out, seed=a.seed)
    for k, v in counts.items():
        print(f"{k:7s} {v:5d} samples -> {Path(a.out) / (k + '.jsonl')}")


def _collect_files(path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    if path.is_file():
        files[path.name] = path.read_text(errors="replace")
        return files
    for p in sorted(path.rglob("*")):
        if p.is_file() and p.stat().st_size < 2_000_000:
            try:
                files[str(p.relative_to(path))] = p.read_text()
            except (UnicodeDecodeError, OSError):
                continue
    return files


def cmd_detect(a):
    from tie.defenses.detector import analyze_files

    files = _collect_files(Path(a.path))
    res = analyze_files(files, threshold=a.threshold)
    if a.json:
        print(json.dumps({"flagged": res.flagged, "evidence": res.evidence(),
                          "other_findings": [f.__dict__ for f in res.findings if f.disposition != "manipulation"]},
                         indent=2, ensure_ascii=False))
    else:
        print(f"{len(files)} file(s) scanned; manipulation findings: {len(res.manipulations)}")
        for f in res.findings:
            tag = "!!" if f.disposition == "manipulation" else "  "
            print(f"{tag} [{f.disposition:12s}] {f.file}:{f.start}-{f.end} score={f.score:.1f} "
                  f"cats={','.join(sorted(f.categories))} conceal={','.join(f.concealment) or '-'}")
            print("     " + f.text[:160].replace("\n", " "))
    sys.exit(1 if res.flagged and a.fail_on_flag else 0)


def cmd_run(a):
    from tie.eval.runner import run_split
    from tie.llm.base import load_model
    from tie.schema import load_samples

    samples = load_samples(a.split)
    if a.filter:
        samples = [s for s in samples if a.filter in s.id]
    if a.types:
        keep = set(a.types.split(","))
        samples = [s for s in samples if s.artifact_type in keep]
    if a.limit:
        samples = samples[: a.limit]
    model = load_model(a.model)
    n = run_split(samples, model, a.defenses.split(","), a.out, build_dir=a.build_dir)
    print(f"wrote {n} new results to {a.out}")


def cmd_report(a):
    from tie.eval.report import make_report

    make_report(a.benchmark, a.results, a.out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="tie", description="Turning injections into evidence")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="generate the benchmark splits")
    b.add_argument("--out", default="benchmark")
    b.add_argument("--seed", type=int, default=0)
    b.set_defaults(fn=cmd_build)

    d = sub.add_parser("detect", help="scan a file or directory for text addressed to an AI analyst")
    d.add_argument("path")
    d.add_argument("--threshold", type=float, default=3.0)
    d.add_argument("--json", action="store_true")
    d.add_argument("--fail-on-flag", action="store_true", help="exit 1 when manipulation is found (CI use)")
    d.set_defaults(fn=cmd_detect)

    r = sub.add_parser("run", help="run triage pipelines on a split")
    r.add_argument("--model", required=True, help="llamacpp:/path.gguf | openai:model@url | scripted:naive")
    r.add_argument("--split", default="benchmark/core.jsonl")
    r.add_argument("--defenses", default="none,quarantine")
    r.add_argument("--out", required=True)
    r.add_argument("--filter", default=None)
    r.add_argument("--types", default=None, help="comma-separated artifact types to keep")
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--build-dir", default="build/binaries")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="aggregate results into tables")
    rp.add_argument("--benchmark", nargs="+", default=["benchmark/core.jsonl", "benchmark/binary.jsonl"])
    rp.add_argument("--results", nargs="+", required=True)
    rp.add_argument("--out", default="results")
    rp.set_defaults(fn=cmd_report)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
