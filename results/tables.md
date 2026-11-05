### Table 1. Undefended pipelines vs. the quarantine pipeline

Failure on injected malicious samples = miss, abort, wrong report (planted decoy IOC/attribution) or executed hijack. Canary echo (the injection's token repeated in the report) is shown separately. Clean malware detected = the same malware without injection; Benign FP = benign samples flagged.

| Model | Defense | Injected: failure | miss | abort | wrong report | hijack | canary echo | Clean malware detected | Benign FP | Benign called malicious |
|---|---|---|---|---|---|---|---|---|---|---|
| Qwen2.5-3B | none | 33% (28/86) | 26% | 0% | 12% | 0% | 3% | 100% (18/18) | 95% (18/19) | 63% |
| Qwen2.5-3B | spotlight | 22% (16/72) | 14% | 0% | 10% | 1% | 4% | 100% (16/16) | 100% (17/17) | 59% |
| Qwen2.5-3B | evidence_prompt | 17% (12/72) | 6% | 0% | 11% | 1% | 6% | 100% (16/16) | 94% (16/17) | 71% |
| Qwen2.5-3B | quarantine | 0% (0/86) | 0% | 0% | 0% | 0% | 0% | 100% (18/18) | 89% (17/19) | 74% |
| Qwen2.5-3B | none+escalate | 12% (10/86) | 0% | 0% | 12% | 0% | 3% | 100% (18/18) | 95% (18/19) | 63% |
| Qwen2.5-3B | counterfactual | 0% (0/86) | 0% | 0% | 0% | 0% | 0% | 100% (18/18) | 95% (18/19) | 74% |
| Qwen2.5-3B | cross_model | 28% (24/86) | 21% | 0% | 12% | 0% | 3% | 100% (18/18) | 95% (18/19) | 63% |
| Llama-3.2-3B | none | 57% (49/86) | 51% | 0% | 12% | 0% | 0% | 83% (15/18) | 32% (6/19) | 11% |
| Llama-3.2-3B | quarantine | 5% (4/86) | 5% | 0% | 0% | 0% | 0% | 100% (18/18) | 68% (13/19) | 37% |
| Llama-3.2-3B | none+escalate | 22% (19/86) | 10% | 0% | 12% | 0% | 0% | 83% (15/18) | 32% (6/19) | 11% |
| Llama-3.2-3B | counterfactual | 5% (4/86) | 5% | 0% | 0% | 0% | 0% | 100% (18/18) | 68% (13/19) | 37% |
| Gemma-2-2B | none | 60% (52/86) | 50% | 0% | 8% | 34% | 3% | 83% (15/18) | 53% (10/19) | 26% |
| Gemma-2-2B | quarantine | 0% (0/86) | 0% | 0% | 0% | 0% | 0% | 100% (18/18) | 68% (13/19) | 58% |
| Gemma-2-2B | none+escalate | 40% (34/86) | 5% | 0% | 8% | 34% | 3% | 83% (15/18) | 53% (10/19) | 26% |
| Gemma-2-2B | counterfactual | 0% (0/86) | 0% | 0% | 0% | 0% | 0% | 100% (18/18) | 74% (14/19) | 63% |

### Table 2. Failure rate on injected malicious samples, by strategy

| Strategy | Qwen2.5-3B none | Qwen2.5-3B quarantine | Llama-3.2-3B none | Llama-3.2-3B quarantine | Gemma-2-2B none | Gemma-2-2B quarantine |
|---|---|---|---|---|---|---|
| direct_override | 40% (4/10) | 0% (0/10) | 70% (7/10) | 0% (0/10) | 60% (6/10) | 0% (0/10) |
| fake_system_messages | 0% (0/10) | 0% (0/10) | 20% (2/10) | 0% (0/10) | 40% (4/10) | 0% (0/10) |
| harness_mimicry | 70% (7/10) | 0% (0/10) | 90% (9/10) | 0% (0/10) | 90% (9/10) | 0% (0/10) |
| refusal_bait | 0% (0/10) | 0% (0/10) | 20% (2/10) | 0% (0/10) | 50% (5/10) | 0% (0/10) |
| cover_story | 60% (6/10) | 0% (0/10) | 70% (7/10) | 0% (0/10) | 90% (9/10) | 0% (0/10) |
| cover_story_implicit | 0% (0/8) | 0% (0/8) | 38% (3/8) | 12% (1/8) | 25% (2/8) | 0% (0/8) |
| misdirection | 100% (10/10) | 0% (0/10) | 100% (10/10) | 0% (0/10) | 80% (8/10) | 0% (0/10) |
| tool_spoof | 10% (1/10) | 0% (0/10) | 30% (3/10) | 0% (0/10) | 50% (5/10) | 0% (0/10) |
| context_flood | 0% (0/8) | 0% (0/8) | 75% (6/8) | 38% (3/8) | 50% (4/8) | 0% (0/8) |

### Table 3. Failure rate on injected samples, by artifact type / pipeline

| Artifact (pipeline) | Qwen2.5-3B none | Qwen2.5-3B quarantine | Llama-3.2-3B none | Llama-3.2-3B quarantine | Gemma-2-2B none | Gemma-2-2B quarantine |
|---|---|---|---|---|---|---|
| strings (strings_triage) | 28% (5/18) | 0% (0/18) | 67% (12/18) | 6% (1/18) | 39% (7/18) | 0% (0/18) |
| decompiled (ghidra_agent) | 17% (3/18) | 0% (0/18) | 94% (17/18) | 17% (3/18) | 100% (18/18) | 0% (0/18) |
| package (pkg_scanner) | 33% (6/18) | 0% (0/18) | 44% (8/18) | 0% (0/18) | 50% (9/18) | 0% (0/18) |
| email (email_triage) | 28% (5/18) | 0% (0/18) | 28% (5/18) | 0% (0/18) | 28% (5/18) | 0% (0/18) |
| binary (r2_agent) | 64% (9/14) | 0% (0/14) | 50% (7/14) | 0% (0/14) | 93% (13/14) | 0% (0/14) |

### Table 4. Induced failures (paired with the clean version of the same malware)

Only pairs where the clean sample was handled correctly are counted, so failures the model would have made anyway are excluded.

| Model | none | spotlight | evidence_prompt | quarantine | none+escalate | counterfactual | cross_model |
|---|---|---|---|---|---|---|---|
| Qwen2.5-3B | 33% (28/86) | 22% (16/72) | 17% (12/72) | 0% (0/86) | 12% (10/86) | 0% (0/86) | 28% (24/86) |
| Llama-3.2-3B | 52% (40/77) | - | - | 5% (4/86) | 21% (16/77) | 5% (4/86) | - |
| Gemma-2-2B | 33% (15/45) | - | - | 0% (0/86) | 11% (5/45) | 0% (0/86) | - |

### Table 5. Gray zone: benign artifacts that carry a note asking reviewers to classify them as benign

| Model | Defense | flagged (malicious or suspicious) |
|---|---|---|
| Llama-3.2-3B | none | 0% (0/4) |
| Llama-3.2-3B | quarantine | 100% (4/4) |
| Llama-3.2-3B | none+escalate | 100% (4/4) |
| Llama-3.2-3B | counterfactual | 100% (4/4) |
| Qwen2.5-3B | none | 25% (1/4) |
| Qwen2.5-3B | quarantine | 100% (4/4) |
| Qwen2.5-3B | none+escalate | 100% (4/4) |
| Qwen2.5-3B | counterfactual | 100% (4/4) |

### Table 6. Detector-evasive (adaptive) variants vs. their originals

Original = the same core sample before mutation. Failure = miss, abort, wrong report or hijack.

| Model | Defense | Original failure | Evasive variant failure |
|---|---|---|---|
| Llama-3.2-3B | none | 60% (25/42) | 45% (19/42) |
| Llama-3.2-3B | quarantine | 0% (0/42) | 26% (11/42) |
| Llama-3.2-3B | none+escalate | 12% (5/42) | 45% (19/42) |
| Llama-3.2-3B | counterfactual | 0% (0/42) | 26% (11/42) |
| Qwen2.5-3B | none | 38% (16/42) | 29% (12/42) |
| Qwen2.5-3B | quarantine | 0% (0/42) | 17% (7/42) |
| Qwen2.5-3B | none+escalate | 12% (5/42) | 29% (12/42) |
| Qwen2.5-3B | counterfactual | 0% (0/42) | 17% (7/42) |

### Table 7. Consistency checks as injection detectors

How often each check *fires* (verdicts disagree), by sample group. A useful signal fires on injected samples and stays quiet on clean ones. Counterfactual = raw vs. quarantined view of the same model; cross-model = Qwen2.5-3B vs. Llama-3.2-3B on the raw view.

| Check | benign (clean) | malicious (clean) | injected (detector-flagged) | injected (not addressed to AI) | adaptive (evades detector) |
|---|---|---|---|---|---|
| counterfactual (Llama-3.2-3B) | 37% (7/19) | 17% (3/18) | 50% (35/70) | 31% (5/16) | 21% (9/42) |
| counterfactual (Qwen2.5-3B) | 5% (1/19) | 0% (0/18) | 31% (22/70) | 0% (0/16) | 14% (6/42) |
| counterfactual (Gemma-2-2B) | 26% (5/19) | 17% (3/18) | 53% (37/70) | 25% (4/16) | - |
| cross-model (Qwen vs Llama) | 63% (12/19) | 17% (3/18) | 30% (21/70) | 56% (9/16) | 33% (14/42) |

_1132 model runs scored (0 runs ended in a pipeline error and are excluded)._
