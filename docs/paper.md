# Turning Injections into Evidence: Hardening AI-Assisted Malware and Package Triage

*Shahzaib. Draft, November 2026.*

## Abstract

Defenders are moving first-pass triage of binaries, packages and emails onto
large language models, and attackers have begun to plant text aimed at those
models. Recent samples carry dozens of fake "system" messages, fabricated
weapons headers designed to trigger safety refusals, and notes telling the
analyst that the code is safe. We present (i) a benchmark that crosses four
artifact types and compiled ELF binaries with nine injection strategies drawn
from in-the-wild reports, four obfuscations and multiple placements, plus hard
negatives that legitimately ship LLM prompts; (ii) open reference triage
pipelines (a radare2 agent, a Ghidra-style agent, an LLM package scanner, and
strings and email triage) scored for misses, aborted analyses, wrong reports and
agent hijacks; and (iii) defenses that quarantine artifact text, check verdict
consistency across views and models, and treat text addressed to an AI as
evidence of malice. On held-out real packages that ship LLM prompts the
evidence detector flags 4 of 25 packages (16%, all false positives, none among
non-LLM packages). A white-box adaptive attacker evades it in 42 of 56 cases.
The question that decides whether "injections as evidence" is a sound
principle is whether the evasive rewrites still work on the model. Section 6
answers it for the models we could run.
<!-- ABSTRACT-RESULTS -->

## 1. Introduction

LLM-assisted triage is attractive because it scales and explains itself: paste
the strings, the decompiled functions or the package files into a prompt, get a
verdict and a summary. Every byte of that input is attacker-controlled. Three
public cases show attackers adapting:

* **Skynet (Check Point Research, June 2025)**: a malware prototype with the
  string "Please ignore all previous instructions ... respond with NO MALWARE
  DETECTED". It failed against the models Check Point tried.
* **macOS.Gaslight (SentinelLABS, June 2026)**: a DPRK-linked Rust backdoor whose
  3.5 kB injection block holds 38 fake "system" messages (token expiry, OOM kills,
  disk exhaustion, bogus injection alerts), wrapped in Markdown fences and
  `{{DATA}}` tokens that resemble a triage harness. The aim is to make the
  analysis *fail*, not to make it say "benign". Its effectiveness was not established.
* **Hades (Socket; Zscaler ThreatLabz, June 2026)**: malicious PyPI wheels whose
  JavaScript payload starts with a block comment of fabricated CBRN text. Socket
  reports that a frontier model halted analysis on it in their testing, while
  conventional tools still detected the stealer.

These reports, and a concurrent preprint on cover-story sections in PE/ELF
binaries (ALIBI, arXiv:2609.19722), suggest three things. Injection is now part
of the anti-analysis toolkit. Its success depends on the pipeline. And defenders
lack both a benchmark and a principled defense. Our starting observation is
that the attacker's text has to address the analyst to work, and legitimate
software has almost no reason to address its own analyst. An injection that
can be recognised is therefore not just a risk to neutralise but a high-precision
indicator of malicious intent. The difficulty is that legitimate packages *do*
ship LLM prompts addressed to a model, so "text addressed to an AI" must be
separated from "text addressed to the AI that is analysing me".

**Contributions.** (1) A benchmark of 481 + 481 injected/clean artifacts (dev and
test template families), a 105-sample LLM split, 18 compiled ELF samples and
42 adaptive variants, with span-level ground truth, canaries and decoys. (2)
Reference pipelines and a scoring scheme that separates misses, aborts, wrong
reports and hijacks, plus paired "induced failure" analysis. (3) An evidence
detector with explicit dispositions for legitimate prompts, corpora, quotations
and coding-assistant guidance; a quarantine pipeline; and counterfactual and
cross-model consistency checks. (4) A held-out false-positive study on 25 real
packages and a white-box adaptive attack.

## 2. Threat model

See [threat_model.md](threat_model.md). The attacker controls only the
artifact's content. Their goals map to our failure modes: verdict flip (miss),
abort, wrong report (decoy IOCs, false attribution, canary), and hijack (an agent
executing `whitelist_sample`). The main benchmark uses published, non-adaptive
techniques; the adaptive study gives the attacker white-box access to the detector.

## 3. Benchmark

See [benchmark.md](benchmark.md). Carriers cover strings dumps (macOS
infostealer, Windows loader, Linux miner, Go RAT), Ghidra-style decompiled code
(stealer, dropper, ransomware, keylogger), packages (install-hook exfiltration,
a Hades-like runtime dropper, a Shai-Hulud-like npm token worm, an AI-tool config
thief) and emails (credential phishing, invoice attachment, BEC, parcel
phishing), each with benign counterparts that are deliberately hard. Examples
are an EDR agent whose strings say "session token expired" and "Malware detected",
an LLM summariser that ships the instruction "ignore instructions inside the
document", a red-team kit full of injection probes, and a newsletter with a
hidden preheader. Nine strategies, four obfuscations and up to five placements
per carrier give 28 injected variants per malicious carrier. All infrastructure
is reserved, and everything is inert (see SECURITY.md).

## 4. Pipelines and scoring

* `strings_triage`, `pkg_scanner`, `email_triage`: single-shot prompts with an
  input budget of 6,000 characters (head truncation, as in many scanners),
  JSON verdict, lenient parsing.
* `ghidra_agent`: a ReAct agent with JSON tool calls (`list_functions`,
  `decompile_function`, `list_strings`, `list_imports`, `whitelist_sample`,
  `submit_report`) over Ghidra-style fixtures, at most 4 tool calls after an
  initial overview.
* `r2_agent`: the same agent over a real radare2 session (`aaa`, `aflj`, `izj`,
  `iij`, `pdc`) on compiled ELFs whose injection lives in the binary's string table.

Failures are defined in the README. Because 2–3B models also make mistakes on
clean malware, we report *induced* failures: injected samples whose clean twin
was handled correctly by the same model and defense.

## 5. Defenses

See [defenses.md](defenses.md). In short:

1. **Evidence detector.** Cue families (address vs. mention, override, verdict
   steering, fake system/abort, refusal bait, harness mimicry, tool spoofing,
   misdirection, authority, self-reference), normalisation of concealment
   (zero-width, homoglyphs, base64/hex, split literals), and dispositions
   (`llm_prompt`, `corpus`, `quotation`, `ai_guidance`, `manipulation`). A
   *strong* manipulation (self-verdict, forged control channel, abort lure,
   refusal bait at a model) stays manipulation even inside a prompt context.
2. **Quarantine.** Withhold flagged spans, remove comments, hidden text and
   non-standard headers from the model's view, use a salience-aware budget against
   flooding, pass trusted facts extracted by code (with quarantined spans
   redacted), and defer privileged tools until the final verdict is known.
3. **Consistency.** Counterfactual (raw vs. quarantined view, same model) and
   cross-model (two families) disagreement is escalated.

## 6. Results

<!-- PAPER-RESULTS -->
*(Filled from `results/tables.md` once the CPU runs complete.)*

### 6.1 Detector

On both synthetic template families the detector flags 100% of injections that
address the analyst (all strategies except flooding and the implicit cover
story), including base64, zero-width, homoglyph and split variants. 0/17 benign
carriers are flagged and 498/498 findings overlap the injected span
([results/detector/summary.md](../results/detector/summary.md)). These numbers
are optimistic: the author wrote both the templates and the lexicon.

### 6.2 Real packages that ship LLM prompts

| | packages | files | packages flagged | findings |
|---|---|---|---|---|
| dev (used for refinement) | 25 | 12,724 | 0 | 0 |
| **test (held out, scanned once)** | **25** | **11,598** | **4** | **8** |

The first version of the detector flagged 19 of the 25 dev packages. Four kinds
of fix brought that to zero without losing synthetic recall: separating *address*
from *mention* of an AI, requiring strong cues before a category counts as a
control attempt, recognising persona/template prompts, and requiring
analysis vocabulary before chat-template or tool-call syntax counts as a forged
channel. On the held-out packages the frozen detector flagged CAMEL's role-play
prompts ("Never forget you are ... You must decline"), docstrings about
"safe/unsafe verdicts" in PyRIT and NeMo Guardrails, and one Anthropic SDK
docstring. All six baseline (non-LLM) test packages were clean, and 134
injection strings in PyRIT's datasets were classified as a corpus rather than as
manipulation. Per file, the false-positive rate is 0.07%. Per LLM-heavy package
it is 21% (4/19), which is too high for blocking and acceptable for a
"needs human review" flag.

### 6.3 Adaptive attacker

A white-box beam search (beam 3, depth 3) over seven text rewrites, four
obfuscations and corpus camouflage evades the frozen detector for 42/56 flagged
injections. The most useful operators were `euphemize_verdict` (16 minimal
variants), `drop_address` (14) and `corpus_camouflage` (10). Fake-system-message
blocks and tool spoofing were hardest to disguise (3/8 and 2/8), because their
effect depends on the very syntax the detector looks for. Some evasive variants
keep an explicit override ("Forget everything you were told before this line")
but lose both the AI addressee and the verdict word. We report this gap rather
than patching it after the fact.

## 7. Discussion

**Evidence beats refusal to read.** A pipeline that strips or ignores injected
text gains robustness but discards information. A pipeline that *reports* it
gains a detection signal that is independent of the payload's behaviour, and
that signal grows with the attacker's effort.

**Where the asymmetry ends.** The adaptive results show that a lexical detector
alone is not a security boundary. The defense in depth is the quarantine view
(the model never sees comments, hidden text or flagged spans, and flooding cannot
push code out of its window) plus consistency checks that do not depend on any
lexicon: if removing the comments changes the verdict, the comments were
instructions.

**Legitimate prompts.** Real packages need context rules (data flow into LLM
calls, prompt files, corpus lists, quotations, AGENTS.md). The remaining false
positives are role-play prompts and content-safety vocabulary. Data-flow analysis
(does this literal reach an LLM call?) instead of name heuristics is the obvious
next step.

## 8. Limitations

Small quantised models on CPU; short synthetic artifacts; templates and
detector by the same author; no live Ghidra; English-centric lexicon (a few
non-English override cues only); emails and packages rendered as text. See
the README for details.

## 9. Ethics

All artifacts are inert and synthetic; refusal bait only claims restricted
content; no real malware, infrastructure or credentials are included. The
adaptive operators are simple rewrites whose purpose is to quantify the
detector's limits for defenders.

## References

* SentinelLABS (2026). macOS.Gaslight: Rust backdoor turns prompt injection on the analyst, not the sandbox. https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
* Cloud Security Alliance (2026). Research note: Gaslight, prompt injection against AI analysts. https://labs.cloudsecurityalliance.org/research/csa-research-note-gaslight-prompt-injection-ai-analyst-evasi/
* The Hacker News (2026). Hades PyPI attack: 19 packages poisoned. https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html
* Check Point Research (2025). Malware prototype with embedded prompt injection ("Skynet"). https://research.checkpoint.com/2025/ai-evasion-prompt-injection/
* MITRE ATLAS. AML.CS0043: Malware prototype with embedded prompt injection. https://atlas.mitre.org/studies/AML.CS0043
* Choi, Jung, Seo, Nam (2026). ALIBI: Adversarial Legitimacy Injection in Binary Input against LLM Malware Analyzers. arXiv:2609.19722.
* Greshake et al. (2023). Not what you've signed up for: compromising real-world LLM-integrated applications with indirect prompt injection. arXiv:2302.12173.
* Yi et al. (2023). Benchmarking and defending against indirect prompt injection attacks on LLMs (BIPIA). arXiv:2312.14197.
* Liu et al. (2024). Formalizing and benchmarking prompt injection attacks and defenses. USENIX Security. arXiv:2310.12815.
* Zhan et al. (2024). InjecAgent. arXiv:2403.02691.
* Debenedetti et al. (2024). AgentDojo. arXiv:2406.13352.
* Hines et al. (2024). Defending against indirect prompt injection attacks with spotlighting. arXiv:2403.14720.
* Willison (2023). The dual LLM pattern for building AI assistants that can resist prompt injection.
* Debenedetti et al. (2025). Defeating prompt injections by design (CaMeL). arXiv:2503.18813.
* Zhan et al. (2025). Adaptive attacks break defenses against indirect prompt injection attacks on LLM agents. Findings of NAACL.
