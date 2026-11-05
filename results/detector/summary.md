# Detector evaluation (no LLM)

## Synthetic `dev` split

| Strategy | none | base64 | zero-width | homoglyph | split |
|---|---|---|---|---|---|
| context_flood | 0/16 |  |  |  |  |
| cover_story | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| cover_story_implicit | 0/32 |  |  |  |  |
| direct_override | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| fake_system_messages | 32/32 |  |  |  |  |
| harness_mimicry | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| misdirection | 32/32 |  |  |  |  |
| refusal_bait | 16/16 |  |  |  |  |
| tool_spoof | 32/32 |  |  |  |  |

Benign carriers flagged: **0/17**. Findings on injected samples that overlap the injected span: **498/498**.

## Synthetic `test` split

| Strategy | none | base64 | zero-width | homoglyph | split |
|---|---|---|---|---|---|
| context_flood | 0/16 |  |  |  |  |
| cover_story | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| cover_story_implicit | 0/32 |  |  |  |  |
| direct_override | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| fake_system_messages | 32/32 |  |  |  |  |
| harness_mimicry | 32/32 | 16/16 | 16/16 | 16/16 | 16/16 |
| misdirection | 32/32 |  |  |  |  |
| refusal_bait | 16/16 |  |  |  |  |
| tool_spoof | 32/32 |  |  |  |  |

Benign carriers flagged: **0/17**. Findings on injected samples that overlap the injected span: **510/510**.

Gray zone (benign artifacts with a note asking reviewers to call them benign): flagged **4/4**.

## Real packages that ship LLM prompts (false-positive study)

Latest releases from PyPI/npm, every text file scanned. *dev* packages were used while refining the context rules; *test* packages were scanned once, after the detector was frozen.

| Split | Category | Packages | Files | Packages with >=1 manipulation finding | Manipulation findings | llm_prompt | corpus | quotation | ai_guidance |
|---|---|---|---|---|---|---|---|---|---|
| dev | llm | 16 | 11920 | 0/16 | 0 | 10 | 7 | 3 | 0 |
| dev | llm-security | 3 | 653 | 0/3 | 0 | 0 | 14 | 0 | 0 |
| dev | baseline | 6 | 151 | 0/6 | 0 | 0 | 0 | 0 | 0 |
| dev | all | 25 | 12724 | 0/25 | 0 | 10 | 21 | 3 | 0 |
| test | llm | 16 | 8256 | 2/16 | 4 | 4 | 0 | 0 | 0 |
| test | llm-security | 3 | 2019 | 2/3 | 4 | 1 | 134 | 0 | 0 |
| test | baseline | 6 | 1323 | 0/6 | 0 | 0 | 0 | 0 | 0 |
| test | all | 25 | 11598 | 4/25 | 8 | 5 | 134 | 0 | 0 |

Held-out false positives (all reported, none fixed after the fact):

* `pypi:anthropic` `anthropic/lib/tools/_beta_session_runner.py` (score 3.4, fake_system,analysis_ref,misdirection): "Enqueue `ev` for dispatch, honoring its evaluated permission.

        A builtin call the server gated behind user confirmation
        (`ev..."
* `pypi:camel-ai` `camel/prompts/ai_society.py` (score 4.0, refusal_bait,address): "===== RULES OF ASSISTANT =====
Never forget you are a {assistant_role} and I am a {user_role}. Never flip roles! Never instruct me!
We share..."
* `pypi:camel-ai` `camel/prompts/ai_society.py` (score 4.8, address,override,refusal_bait): "===== RULES OF USER =====
Never forget you are a {user_role} and I am a {assistant_role}. Never flip roles! You will always instruct me.
We..."
* `pypi:camel-ai` `camel/prompts/code.py` (score 4.8, address,override,refusal_bait): "Never forget you are a person working in {domain} and I am a Computer programmer. Never flip roles! You will always instruct me.
We share a..."
* `pypi:pyrit` `pyrit/datasets/seed_datasets/remote/hixstest_dataset.py` (score 4.2, verdict_steer,address): "Loader for the HiXSTest (Hindi Exaggerated-Safety Test) dataset from HuggingFace.

    HiXSTest is a manually-curated set of 50 exagger..."
* `pypi:pyrit` `pyrit/datasets/seed_datasets/remote/sgxstest_dataset.py` (score 4.2, verdict_steer,address): "Loader for the SGXSTest (Singapore exaggerated-safety test) dataset from HuggingFace.

    SGXSTest contains 100 manually-curated safe/..."
* `pypi:pyrit` `pyrit/memory/memory_interface.py` (score 3.7, verdict_steer,analysis_ref): "Build a validated backend-specific attack-label condition.

        Returns:
            list[Any]: The backend-specific label cond..."
* `pypi:nemoguardrails` `nemoguardrails/llm/output_parsers.py` (score 3.7, verdict_steer,analysis_ref): "Helper function to extract the safe/unsafe verdict for a given field.

    Args:
        response: The model response text, with or without..."

## Adaptive attacker vs. the frozen detector

White-box beam search (beam 3, depth 3) over text rewrites, obfuscations and corpus camouflage.

| Strategy | evaded / attacked |
|---|---|
| cover_story | 8/8 |
| direct_override | 8/8 |
| fake_system_messages | 3/8 |
| harness_mimicry | 8/8 |
| misdirection | 5/8 |
| refusal_bait | 8/8 |
| tool_spoof | 2/8 |
| **total** | **42/56** |

Operators in the minimal evasive variants: `euphemize_verdict` x16, `drop_address` x14, `corpus_camouflage` x10, `soften_override` x4, `drop_self_ref` x4, `third_person` x2, `strip_roles` x2, `split` x1

