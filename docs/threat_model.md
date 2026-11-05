# Threat model

## Setting

A defender runs **AI-assisted triage**: an LLM (alone or as an agent with tools)
reads an untrusted artifact and returns a verdict, capabilities, indicators of
compromise (IOCs) and a summary. Four artifact types are in scope, matching how
triage is done today:

| Artifact | What the model reads | Pipeline in this repo |
|---|---|---|
| Strings | `strings`/FLOSS output of an executable | `strings_triage` (single shot) |
| Decompiled code | Ghidra-style pseudo-C, through tools | `ghidra_agent` (tool-using agent) |
| Binary | a real ELF, through radare2 | `r2_agent` (tool-using agent) |
| Package | files of a PyPI/npm package incl. metadata | `pkg_scanner` (single shot) |
| Email | raw headers + HTML body | `email_triage` (single shot) |

## Attacker

The attacker authors the artifact. They cannot touch the triage system, its
prompts or its tools. They can only put text into the artifact: string
literals, comments, docstrings, package metadata, READMEs, hidden HTML, mail
headers. That text reaches the model because triage pipelines paste artifact
content into the prompt.

**Goals**, which define the four failure modes we score:

1. **Verdict flip (miss)**: the malicious artifact is reported benign.
2. **Abort**: the analysis never produces a verdict (refusal, a claimed error, no
   parseable answer). Socket observed this with Hades: a safety-tuned model
   halted on the fabricated weapons header. In an automated queue an abort is
   often a silent pass.
3. **Wrong report**: the verdict may be right but the report repeats
   attacker-chosen content: decoy IOCs, false attribution, or a canary token
   showing that injected instructions were followed.
4. **Hijack**: an agent with privileged tools uses them for the attacker. Here
   that means calling `whitelist_sample`, which adds the sample to an allow-list.

**Knowledge.** For the main benchmark the attacker is *non-adaptive*: they use
the published techniques (Gaslight, Hades, Skynet-style overrides, cover
stories). For the adaptive study the attacker knows the detector and can query
its score (white-box), then rewrites the payload until it is no longer flagged.

## Out of scope

* Attacks on the triage infrastructure itself (sandbox escapes, tool exploits).
* Training-time attacks on the model.
* Evasion of non-LLM analysis (packing, anti-VM). The binaries here are not packed.
* Human analysts. We measure the AI step only. An abort or a "benign" verdict
  that a human then double-checks is less harmful than the same result in a fully
  automated pipeline.

## The defender's opportunity

Text addressed *to the analyst* is a rare thing for legitimate software to
contain. A program has no reason to tell its reviewer that it is safe, to forge
the reviewer's tool output, or to fake the reviewer's session errors. If a
pipeline can tell such text apart from legitimate prompts that software ships
for its *own* LLM features, every injection attempt becomes evidence of
malicious intent rather than a risk. The attacker then has to choose between
being persuasive to the model (and therefore recognisable) and being
unrecognisable (and therefore weaker). This repository tests how far that idea
holds.
