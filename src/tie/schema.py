"""Core data types shared by the benchmark, pipelines, defenses and scoring."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

ARTIFACT_TYPES = ("strings", "decompiled", "package", "email", "binary")
LABELS = ("malicious", "benign")
VERDICTS = ("malicious", "suspicious", "benign")
STATUSES = ("completed", "aborted", "error")


@dataclass
class Injection:
    """Ground truth for an injected payload."""

    strategy: str
    goal: str  # verdict_flip | abort | misdirect | hijack
    placement: str
    obfuscation: str = "none"
    template_id: str = ""
    text: str = ""  # payload before obfuscation / slot formatting
    canary: str | None = None
    decoy_iocs: list[str] = field(default_factory=list)
    decoy_attribution: str | None = None
    addresses_ai: bool = True  # does the payload explicitly address an AI/analyst?
    spans: list[dict[str, Any]] = field(default_factory=list)  # {"file","start","end"}
    mutations: list[str] = field(default_factory=list)  # adaptive operators applied


@dataclass
class Sample:
    id: str
    artifact_type: str
    label: str  # malicious | benign
    base_id: str
    scenario: str
    files: dict[str, str]
    capabilities: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    injection: Injection | None = None
    tags: list[str] = field(default_factory=list)
    binary_source: str | None = None  # C source (binary artifacts only)

    @property
    def injected(self) -> bool:
        return self.injection is not None

    def text(self) -> str:
        """All files concatenated (used by single-view baselines)."""
        if len(self.files) == 1:
            return next(iter(self.files.values()))
        return "\n".join(f"===== {name} =====\n{body}" for name, body in self.files.items())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Sample":
        d = dict(d)
        inj = d.get("injection")
        d["injection"] = Injection(**inj) if inj else None
        return cls(**d)


@dataclass
class TriageReport:
    """Normalised output of any triage pipeline for one sample."""

    sample_id: str
    pipeline: str
    model: str
    defense: str
    verdict: str | None = None
    status: str = "completed"
    abort_reason: str | None = None
    confidence: float | None = None
    capabilities: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    attribution: str | None = None
    summary: str = ""
    raw_output: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    llm_verdict: str | None = None  # verdict before any defense escalation
    elapsed_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TriageReport":
        return cls(**d)


def write_jsonl(path: str | Path, rows: Iterable[Any]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            if hasattr(row, "to_dict"):
                row = row.to_dict()
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_samples(path: str | Path) -> list[Sample]:
    return [Sample.from_dict(d) for d in read_jsonl(path)]
