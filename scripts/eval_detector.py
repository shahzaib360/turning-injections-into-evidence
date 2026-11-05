#!/usr/bin/env python3
"""Detector-only evaluation (no LLM): synthetic recall/FP, span precision, real-world FP.

Writes results/detector/summary.md and summary.json.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tie.defenses.detector import analyze_sample  # noqa: E402
from tie.schema import load_samples  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def overlaps(f, spans) -> bool:
    return any(f.file == sp["file"] and f.start < sp["end"] and sp["start"] < f.end for sp in spans)


def synthetic(split: str) -> dict:
    samples = load_samples(ROOT / "benchmark" / f"{split}.jsonl")
    rec = collections.defaultdict(lambda: [0, 0])
    span_hits = span_total = 0
    fp = []
    benign_n = 0
    for s in samples:
        res = analyze_sample(s)
        if s.injection:
            key = (s.injection.strategy, s.injection.obfuscation)
            rec[key][1] += 1
            rec[key][0] += int(res.flagged)
            if s.injection.spans:
                for f in res.manipulations:
                    span_total += 1
                    span_hits += int(overlaps(f, s.injection.spans))
        elif s.label == "benign":
            benign_n += 1
            if res.flagged:
                fp.append(s.id)
    return {"recall": {f"{k[0]}|{k[1]}": v for k, v in rec.items()}, "fp": fp, "benign_n": benign_n,
            "span_precision": [span_hits, span_total]}


def realworld() -> dict:
    out = {}
    for split in ("dev", "test"):
        p = ROOT / "results" / "realworld" / f"scan_{split}.json"
        if p.exists():
            out[split] = json.loads(p.read_text())
    return out


def main():
    lines = ["# Detector evaluation (no LLM)\n"]
    summary = {}
    for split in ("dev", "test"):
        r = synthetic(split)
        summary[split] = r
        lines.append(f"## Synthetic `{split}` split\n")
        lines.append("| Strategy | none | base64 | zero-width | homoglyph | split |")
        lines.append("|---|---|---|---|---|---|")
        strategies = sorted({k.split("|")[0] for k in r["recall"]})
        for st in strategies:
            row = [st]
            for obf in ("none", "base64", "zero_width", "homoglyph", "split"):
                v = r["recall"].get(f"{st}|{obf}")
                row.append(f"{v[0]}/{v[1]}" if v else "")
            lines.append("| " + " | ".join(row) + " |")
        sp = r["span_precision"]
        lines.append(f"\nBenign carriers flagged: **{len(r['fp'])}/{r['benign_n']}**. "
                     f"Findings on injected samples that overlap the injected span: **{sp[0]}/{sp[1]}**.\n")
    gray = load_samples(ROOT / "benchmark" / "gray.jsonl")
    g = sum(analyze_sample(s).flagged for s in gray)
    lines.append(f"Gray zone (benign artifacts with a note asking reviewers to call them benign): flagged **{g}/{len(gray)}**.\n")
    summary["gray"] = [g, len(gray)]

    rw = realworld()
    if rw:
        lines.append("## Real packages that ship LLM prompts (false-positive study)\n")
        lines.append("Latest releases from PyPI/npm, every text file scanned. *dev* packages were used while "
                     "refining the context rules; *test* packages were scanned once, after the detector was frozen.\n")
        lines.append("| Split | Category | Packages | Files | Packages with >=1 manipulation finding | Manipulation findings | llm_prompt | corpus | quotation | ai_guidance |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for split, rows in rw.items():
            rows = [x for x in rows if "error" not in x]
            for cat in ("llm", "llm-security", "baseline", "all"):
                sel = rows if cat == "all" else [x for x in rows if x["category"] == cat]
                if not sel:
                    continue
                disp = collections.Counter()
                for x in sel:
                    disp.update(x["dispositions"])
                flagged = sum(1 for x in sel if x["manipulation_findings"])
                lines.append(
                    f"| {split} | {cat} | {len(sel)} | {sum(x['files'] for x in sel)} | {flagged}/{len(sel)} | "
                    f"{disp.get('manipulation', 0)} | {disp.get('llm_prompt', 0)} | {disp.get('corpus', 0)} | "
                    f"{disp.get('quotation', 0)} | {disp.get('ai_guidance', 0)} |"
                )
        test_rows = [x for x in rw.get("test", []) if x.get("manipulation_findings")]
        if test_rows:
            lines.append("\nHeld-out false positives (all reported, none fixed after the fact):\n")
            for x in test_rows:
                for f in x["manipulation_findings"]:
                    cats = ",".join(k for k in f["categories"] if k not in ("mention",))
                    lines.append(f"* `{x['package']}` `{f['file']}` (score {f['score']}, {cats}): "
                                 f"\"{f['excerpt'][:140].strip()}...\"")
        summary["realworld"] = {
            split: {"packages": len(rows), "flagged": sum(1 for x in rows if x.get("manipulation_findings")),
                    "files": sum(x.get("files", 0) for x in rows),
                    "findings": sum(len(x.get("manipulation_findings", [])) for x in rows)}
            for split, rows in rw.items()
        }
    adaptive = ROOT / "results" / "adaptive" / "search.json"
    if adaptive.exists():
        res = json.loads(adaptive.read_text())
        by = collections.defaultdict(lambda: [0, 0])
        ops = collections.Counter()
        for r in res:
            by[r["strategy"]][1] += 1
            by[r["strategy"]][0] += int(r["evaded"])
            if r["ops"]:
                ops.update(r["ops"])
        lines.append("\n## Adaptive attacker vs. the frozen detector\n")
        lines.append("White-box beam search (beam 3, depth 3) over text rewrites, obfuscations and corpus camouflage.\n")
        lines.append("| Strategy | evaded / attacked |")
        lines.append("|---|---|")
        for k, (e, n) in sorted(by.items()):
            lines.append(f"| {k} | {e}/{n} |")
        tot = [sum(v[0] for v in by.values()), sum(v[1] for v in by.values())]
        lines.append(f"| **total** | **{tot[0]}/{tot[1]}** |")
        lines.append("\nOperators in the minimal evasive variants: " + ", ".join(f"`{k}` x{v}" for k, v in ops.most_common()) + "\n")
        summary["adaptive"] = {"by_strategy": dict(by), "total": tot, "ops": dict(ops)}
    out = ROOT / "results" / "detector"
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
