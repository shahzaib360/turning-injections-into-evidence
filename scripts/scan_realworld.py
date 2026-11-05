#!/usr/bin/env python3
"""False-positive study: run the detector over real packages that ship LLM prompts.

Downloads the latest release of each package (PyPI wheel/sdist or npm tarball)
into a cache directory outside the repository, scans every text file, and
writes per-package counts by disposition plus every ``manipulation`` finding
for manual review.

Packages are split into ``dev`` (used while refining the detector's context
rules) and ``test`` (scanned only for the final numbers).

Usage: python scripts/scan_realworld.py --cache ~/.cache/tie-realworld --out results/realworld
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tie.defenses.detector import analyze_files  # noqa: E402

# (ecosystem:name, split, category)
PACKAGES = [
    # LLM frameworks, SDKs and agents that ship prompts (hard negatives)
    ("pypi:langchain-core", "dev", "llm"),
    ("pypi:langchain", "test", "llm"),
    ("pypi:langchain-community", "test", "llm"),
    ("pypi:llama-index-core", "dev", "llm"),
    ("pypi:dspy", "test", "llm"),
    ("pypi:crewai", "dev", "llm"),
    ("pypi:autogen-agentchat", "test", "llm"),
    ("pypi:semantic-kernel", "dev", "llm"),
    ("pypi:haystack-ai", "test", "llm"),
    ("pypi:guidance", "dev", "llm"),
    ("pypi:instructor", "test", "llm"),
    ("pypi:openai", "dev", "llm"),
    ("pypi:anthropic", "test", "llm"),
    ("pypi:litellm", "dev", "llm"),
    ("pypi:smolagents", "test", "llm"),
    ("pypi:pydantic-ai-slim", "dev", "llm"),
    ("pypi:langgraph", "test", "llm"),
    ("pypi:mem0ai", "dev", "llm"),
    ("pypi:ragas", "test", "llm"),
    ("pypi:deepeval", "dev", "llm"),
    ("pypi:aider-chat", "test", "llm"),
    ("pypi:open-interpreter", "dev", "llm"),
    ("pypi:marvin", "test", "llm"),
    ("pypi:outlines", "dev", "llm"),
    ("pypi:camel-ai", "test", "llm"),
    ("pypi:browser-use", "dev", "llm"),
    # LLM security / red-team tooling (contain real injection strings)
    ("pypi:garak", "dev", "llm-security"),
    ("pypi:pyrit", "test", "llm-security"),
    ("pypi:llm-guard", "dev", "llm-security"),
    ("pypi:nemoguardrails", "test", "llm-security"),
    ("pypi:guardrails-ai", "dev", "llm-security"),
    ("pypi:rebuff", "test", "llm-security"),
    # npm
    ("npm:openai", "dev", "llm"),
    ("npm:@anthropic-ai/sdk", "test", "llm"),
    ("npm:langchain", "dev", "llm"),
    ("npm:@langchain/core", "test", "llm"),
    ("npm:ai", "dev", "llm"),
    ("npm:llamaindex", "test", "llm"),
    # baseline: popular packages without LLM features
    ("pypi:requests", "dev", "baseline"),
    ("pypi:flask", "test", "baseline"),
    ("pypi:click", "dev", "baseline"),
    ("pypi:rich", "test", "baseline"),
    ("pypi:httpx", "dev", "baseline"),
    ("pypi:pyyaml", "test", "baseline"),
    ("pypi:black", "dev", "baseline"),
    ("pypi:pytest", "test", "baseline"),
    ("pypi:jinja2", "dev", "baseline"),
    ("pypi:urllib3", "test", "baseline"),
    ("npm:express", "dev", "baseline"),
    ("npm:lodash", "test", "baseline"),
]

TEXT_EXT = (
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".json", ".md", ".txt", ".rst", ".yaml", ".yml",
    ".toml", ".cfg", ".jinja", ".jinja2", ".j2", ".prompt", ".tmpl", "METADATA", "PKG-INFO",
)
MAX_FILE = 1_000_000


def fetch_pypi(name: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    existing = [p for p in dest.iterdir() if p.suffix in (".whl", ".gz", ".zip")]
    if existing:
        return existing[0]
    for args in (["--only-binary=:all:"], ["--no-binary=:all:"]):
        r = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--no-deps", "-q", "--dest", str(dest), *args, name],
            capture_output=True,
            text=True,
        )
        files = [p for p in dest.iterdir() if p.suffix in (".whl", ".gz", ".zip")]
        if r.returncode == 0 and files:
            return files[0]
    raise RuntimeError(f"pip download failed for {name}: {r.stderr[-300:]}")


def fetch_npm(name: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "package.tgz"
    if tgz.exists():
        return tgz
    meta = json.loads(urllib.request.urlopen(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest", timeout=60).read())
    data = urllib.request.urlopen(meta["dist"]["tarball"], timeout=300).read()
    tgz.write_bytes(data)
    (dest / "version.txt").write_text(meta.get("version", "?"))
    return tgz


def read_archive(path: Path) -> dict[str, str]:
    files: dict[str, str] = {}

    def keep(name: str, size: int) -> bool:
        return size <= MAX_FILE and (name.endswith(TEXT_EXT) or name.rsplit("/", 1)[-1] in ("METADATA", "PKG-INFO"))

    if path.suffix in (".whl", ".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if keep(info.filename, info.file_size):
                    files[info.filename] = z.read(info).decode("utf-8", "replace")
    else:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.isfile() and keep(m.name, m.size):
                    fh = t.extractfile(m)
                    if fh:
                        files[m.name] = fh.read().decode("utf-8", "replace")
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default=str(Path.home() / ".cache" / "tie-realworld"))
    ap.add_argument("--out", default="results/realworld")
    ap.add_argument("--split", default="all", choices=["all", "dev", "test"])
    a = ap.parse_args()
    cache, out = Path(a.cache), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for spec, split, category in PACKAGES:
        if a.split != "all" and split != a.split:
            continue
        eco, name = spec.split(":", 1)
        d = cache / eco / name.replace("/", "__")
        t0 = time.time()
        try:
            arc = fetch_pypi(name, d) if eco == "pypi" else fetch_npm(name, d)
            files = read_archive(arc)
        except Exception as e:  # network or packaging problem: record and continue
            rows.append({"package": spec, "split": split, "category": category, "error": str(e)[:300]})
            print(f"{spec}: ERROR {e}", file=sys.stderr)
            continue
        res = analyze_files(files)
        counts: dict[str, int] = {}
        for f in res.findings:
            counts[f.disposition] = counts.get(f.disposition, 0) + 1
        version = arc.name if eco == "pypi" else (d / "version.txt").read_text()
        rows.append(
            {
                "package": spec,
                "split": split,
                "category": category,
                "artifact": version,
                "files": len(files),
                "chars": sum(len(v) for v in files.values()),
                "dispositions": counts,
                "manipulation_findings": [
                    {"file": f.file, "score": f.score, "categories": f.categories, "concealment": f.concealment,
                     "excerpt": f.text[:240]}
                    for f in res.manipulations
                ],
                "seconds": round(time.time() - t0, 1),
            }
        )
        print(f"{spec:32s} {split:4s} files={len(files):5d} {counts}", file=sys.stderr)
    (out / "scan.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    ok = [r for r in rows if "error" not in r]
    for sp in ("dev", "test"):
        sel = [r for r in ok if r["split"] == sp]
        flagged = [r for r in sel if r["manipulation_findings"]]
        print(f"{sp}: {len(flagged)}/{len(sel)} packages with >=1 manipulation finding; "
              f"{sum(len(r['manipulation_findings']) for r in sel)} findings over {sum(r['files'] for r in sel)} files")


if __name__ == "__main__":
    main()
