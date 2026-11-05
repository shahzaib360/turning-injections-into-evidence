#!/usr/bin/env python3
"""Adaptive attack against the detector, then hand the evasive variants to the LLM runs.

1. For every detector-flagged injected sample in the core split, beam-search the
   mutation operators in ``tie.bench.adaptive`` for a variant that is no longer
   flagged.
2. Write the evasive variants to ``benchmark/adaptive.jsonl``. Run them through
   the LLM pipelines with ``tie run --split benchmark/adaptive.jsonl`` to see
   whether evading the detector also costs the attack its effect on the model.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tie.bench.adaptive import search, variant_sample  # noqa: E402
from tie.defenses.detector import analyze_sample  # noqa: E402
from tie.schema import load_samples, write_jsonl  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="benchmark/core.jsonl")
    ap.add_argument("--out", default="results/adaptive")
    ap.add_argument("--variants", default="benchmark/adaptive.jsonl")
    ap.add_argument("--beam", type=int, default=3)
    ap.add_argument("--depth", type=int, default=3)
    a = ap.parse_args()
    samples = [s for s in load_samples(a.split) if s.injection is not None]
    results, variants = [], []
    for s in samples:
        if not analyze_sample(s).flagged:
            continue  # nothing to evade (context_flood, cover_story_implicit)
        r = search(s, beam=a.beam, depth=a.depth)
        vs = variant_sample(s, r)
        if vs is not None:
            variants.append(vs)
        r.pop("_variant", None)
        results.append(r)
        print(f"{s.id[:70]:70s} evaded={r['evaded']!s:5s} ops={r['ops']} evals={r['evaluated']}", file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "search.json").write_text(json.dumps(results, indent=1, ensure_ascii=False))
    write_jsonl(a.variants, variants)

    by = collections.defaultdict(lambda: [0, 0])
    ops = collections.Counter()
    for r in results:
        by[r["strategy"]][1] += 1
        by[r["strategy"]][0] += int(r["evaded"])
        if r["ops"]:
            ops.update(r["ops"])
    print("strategy               evaded/attacked")
    for k, (e, n) in sorted(by.items()):
        print(f"{k:22s} {e:3d}/{n:3d}")
    tot = sum(v[0] for v in by.values()), sum(v[1] for v in by.values())
    print(f"TOTAL                  {tot[0]:3d}/{tot[1]:3d}")
    print("operators in minimal evasive variants:", dict(ops.most_common()))
    print(f"{len(variants)} evasive variants written to {a.variants}")


if __name__ == "__main__":
    main()
