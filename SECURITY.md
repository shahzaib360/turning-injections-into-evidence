# Safety and responsible use

This repository studies text that malware plants for AI analysts. It is built
for defenders, and it is designed so that nothing in it can harm a system.

## What the benchmark contains and what it does not

* **Synthetic, inert artifacts only.** Strings dumps, decompiler output, package
  files and emails are textual renderings written for static triage. They are
  never meant to be executed, and the package files are stored as strings inside
  JSONL, so they cannot be installed or imported by accident.
* **No live infrastructure.** Attacker hosts use the reserved `.invalid` / `.example`
  names (RFC 2606/6761) and IPs come from the documentation ranges
  192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737). Tokens and keys are
  placeholders such as `AAFAKE_PLACEHOLDER_TOKEN_NOT_REAL`. A unit test enforces this.
* **No real malware.** No sample, hash or payload from a real campaign is included.
  The "obfuscated payload" in one package carrier decodes to an inert comment.
* **Refusal bait only *claims* restricted content.** The Hades-style carriers state
  that weapons material follows and then show `[REDACTED ...]` placeholders. No
  hazardous information is generated, and a unit test checks for the placeholders.
* **Compiled binaries are inert.** The C programs used for the radare2 agent gate
  every side effect (`system`, file writes) behind a `volatile` flag that is never
  set, point only at `.invalid` hosts, and are only analysed statically. Binaries
  are built locally by the harness and are not committed.

## Dual use

The injection strategies mirror techniques already published by SentinelLABS
(macOS.Gaslight), Socket (Hades), Check Point ("Skynet") and Koi Security. The
adaptive operators are simple text rewrites (drop the vocative, soften the
verdict, move the text into a test fixture). The repository documents where the
proposed detector fails so that defenders do not over-trust it. It is not a
tool for evading real products.

## Reporting

If you find a way in which the material here could cause harm, or a weakness in
a triage product that this benchmark helped you find, please open an issue
(without exploit details) or contact the maintainer privately first, and follow
coordinated disclosure with the affected vendor.
