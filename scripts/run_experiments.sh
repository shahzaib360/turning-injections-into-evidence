#!/usr/bin/env bash
# Reproduce the CPU-only evaluation reported in README.md (ordered by priority).
# Requires: pip install -e ".[local]", radare2, and the three GGUF models below.
set -euo pipefail
M=${MODELS_DIR:-/opt/models}
Q="llamacpp:$M/qwen2.5-3b-instruct-q4_k_m.gguf"
L="llamacpp:$M/Llama-3.2-3B-Instruct-Q4_K_M.gguf"
G="llamacpp:$M/gemma-2-2b-it-Q4_K_M.gguf"
OUT=${OUT:-results/raw}
mkdir -p "$OUT"

# 1. undefended baseline + quarantine pipeline (two model families)
tie run --model "$Q" --split benchmark/core.jsonl     --defenses none,quarantine --out "$OUT/qwen2.5-3b.jsonl"
tie run --model "$L" --split benchmark/core.jsonl     --defenses none,quarantine --out "$OUT/llama3.2-3b.jsonl"
# 2. detector-evasive variants from scripts/run_adaptive.py
tie run --model "$Q" --split benchmark/adaptive.jsonl --defenses none,quarantine --out "$OUT/adaptive-qwen2.5-3b.jsonl"
tie run --model "$L" --split benchmark/adaptive.jsonl --defenses none,quarantine --out "$OUT/adaptive-llama3.2-3b.jsonl"
# 3. radare2 agent on compiled ELF carriers
tie run --model "$Q" --split benchmark/binary.jsonl   --defenses none,quarantine --out "$OUT/qwen2.5-3b.jsonl"
tie run --model "$L" --split benchmark/binary.jsonl   --defenses none,quarantine --out "$OUT/llama3.2-3b.jsonl"
# 4. gray zone (benign artifacts carrying a note to reviewers)
tie run --model "$Q" --split benchmark/gray.jsonl     --defenses none,quarantine --out "$OUT/gray-qwen2.5-3b.jsonl"
tie run --model "$L" --split benchmark/gray.jsonl     --defenses none,quarantine --out "$OUT/gray-llama3.2-3b.jsonl"
# 5. prompt-level defenses (ablation) on the primary model
tie run --model "$Q" --split benchmark/core.jsonl     --defenses spotlight,evidence_prompt --out "$OUT/qwen2.5-3b.jsonl"
# 6. third model family
tie run --model "$G" --split benchmark/core.jsonl     --defenses none,quarantine --out "$OUT/gemma2-2b.jsonl"
tie run --model "$G" --split benchmark/binary.jsonl   --defenses none,quarantine --out "$OUT/gemma2-2b.jsonl"
