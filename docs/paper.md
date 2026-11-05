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
evidence of malice. On two 3B open models, published-style injections defeat
33% (Qwen2.5-3B) and 57% (Llama-3.2-3B) of injected malware samples in
undefended pipelines, including a radare2 agent on real ELF binaries. The
quarantine pipeline reduces this to 0% and 5%, at the cost of more false
positives for the better-calibrated model. Prompt-only defenses
(spotlighting, an "evidence" instruction) leave planted decoys in almost every
report. On held-out real packages that ship LLM prompts, the evidence detector
flags 4 of 25 packages (all false positives, none among non-LLM packages). A
white-box adaptive attacker evades it in 42 of 56 cases. Evasion costs the
attacker about a quarter of the injection's effect, but 17–26% of the evasive
variants still get through the full pipeline. Injections are good evidence
against today's attacks, not a security boundary.

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

Setup: Qwen2.5-3B-Instruct, Llama-3.2-3B-Instruct and Gemma-2-2B-it, 4-bit
GGUF, llama.cpp on 4 CPU cores, temperature 0, one run per sample and condition.
The core split has 72 injected malicious samples (2 carriers × 9 strategies per
type), 16 clean malicious and 17 benign. The binary split adds 14 injected, 2
clean malicious and 2 benign ELF samples for the radare2 agent. Confidence
intervals are wide at these sample sizes: the Wilson 95% half-width is about ±10
points for proportions out of 86, ±15 out of 42, and ±25–30 for per-strategy
cells of 8–10 samples. We therefore emphasise differences that are large and
consistent across models. All tables:
[results/tables.md](../results/tables.md).

### 6.0 Vulnerability of undefended pipelines and the effect of quarantine

| injected malware defeated (of 86) | Qwen2.5-3B | Llama-3.2-3B | Gemma-2-2B |
|---|---|---|---|
| no defense | 33% | 57% | _pending_ |
| spotlighting (datamark + delimiters)¹ | 22% | - | - |
| spotlighting + evidence prompt¹ | 17% | - | - |
| detector escalation of the raw verdict | 12% | 22% | _pending_ |
| quarantine pipeline | **0%** | **5%** | _pending_ |
| clean malware detected (none → quarantine) | 100% → 100% | 83% → 100% | _pending_ |
| benign flagged (none → quarantine) | 95% → 89% | 32% → 68% | _pending_ |

¹ Run on the 72 core samples only (no ELF binaries). On the same 72 samples
Qwen's undefended failure is 26%, detector escalation 11%, quarantine 0% and
cross-model 24%.

*Prompt-only defenses.* Spotlighting barely moves the needle (26% → 22%), and
harness mimicry got slightly *more* effective (5/8 → 6/8). Adding the evidence
framing helps more (17%): override and cover-story flips disappear (2/8 → 0/8,
4/8 → 0/8). But misdirection is untouched, with decoys in 8/8 and 7/8 reports.
A model that is told the text is untrusted still copies "facts" out of it. Only
removing the text from the view (quarantine) prevents that.

*By strategy* (no defense, Qwen / Llama): harness mimicry 70% / 90%,
cover story 60% / 70%, direct override 40% / 70%, misdirection 100% / 100%
(decoy IOCs or attribution in the report), tool spoofing 10% / 30%,
implicit cover story 0% / 38%, context flooding 0% / 75%, and fake system
messages and refusal bait 0% / 20% each. The two techniques seen in the most
prominent 2026 samples, Gaslight's fake errors and Hades' refusal bait, were the
least effective against these models. Neither model ever refused or claimed an
error, so the abort column is empty. This matches the public assessment that
these attacks are unreliable. It may change with more safety-tuned models
(Socket reports a frontier model halting on Hades), and our harness records
aborts separately so the question can be re-run.

*By pipeline* (no defense → quarantine): strings triage 28% → 0% (Qwen),
67% → 6% (Llama); Ghidra-style agent 17% → 0%, 94% → 17%; package scanner
33% → 0%, 44% → 0%; email triage 28% → 0%, 28% → 0%; radare2 agent on compiled
ELFs 64% → 0%, 50% → 0%. The agents were not hijacked in any undefended run
(no executed `whitelist_sample` on injected malware), although Gemma called the
tool spuriously during piloting. Under quarantine the tool is deferred and never
executed on malware.

*Residual failures under quarantine* (Llama, 4/86) are three context-flooding
samples and one implicit cover story: the two strategies that do not address the
analyst and so are not quarantined. The flood works by *framing* rather than
truncation. The model described a credential stealer as "automated build system
output with copyright notice".

*Costs.* Quarantine raised Llama's benign flag rate from 32% to 68%, mostly on
hard negatives (LLM CLI, backup agent, red-team kit, model downloader). Qwen
flags 89–95% of benign artifacts under every configuration. Small models are
poorly calibrated triage engines. The relevant comparison is therefore *induced*
failure (Table 4 in results), which tells the same story: 33% → 0% (Qwen) and
52% → 5% (Llama).

### 6.0b Consistency checks

Cross-model consistency (union of Qwen and Llama verdicts, disagreement
escalated) lowered Qwen's failure only from 33% to 28%. The same injections
(harness mimicry, cover stories) fool both families, and the planted decoys
remain in the report. As a detector, cross-model disagreement fires on 63% of
benign files, because the two models' base rates differ so much.

The counterfactual check compares the raw-view verdict with the quarantined-view
verdict of the same model. For Qwen it fires on 31% of detector-flagged
injections and 14% of the adaptive (detector-evading) variants, but on 0% of clean
malware and 5% of benign files. That is a lexicon-independent signal, though a
weak one. For Llama it is noisy (37% of benign files, 17% of clean malware): the
model's verdict depends on the view even without an injection.

### 6.0c Gray zone

Four benign artifacts carry a note asking reviewers to classify them as benign.
Without defenses, Qwen flagged 1/4 of them (versus 95% of benign artifacts
without such a note) and Llama 0/4. The note works on benign files too. The
evidence pipeline flags 4/4 for review. Whether that is a false positive is a
policy question; we count it separately.

### 6.0d Adaptive variants against the models

| injected malware defeated (42 detector-evading variants) | original | evasive variant |
|---|---|---|
| Qwen, no defense | 38% | 29% |
| Qwen, quarantine pipeline | 0% | 17% |
| Llama, no defense | 60% | 45% |
| Llama, quarantine pipeline | 0% | 26% |

The attacker pays for evading the detector: the rewritten payloads lose about a
quarter of their effect on the undefended pipelines. But the full pipeline
falls from 0% to 17–26% failure. Most of the successful variants are
misdirection moved into a test-fixture file (5/5 for Qwen) and harness mimicry
without role tokens. The misdirection case exposes a design flaw: trusted facts
are extracted from all non-quarantined text, so once the detector is evaded the
decoy domain is promoted to a "trusted" network indicator. Facts should come
only from executable context (URLs in code statements, imports), never from
prose or data files.

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
