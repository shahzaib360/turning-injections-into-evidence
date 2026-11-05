"""Detector: text addressed to an AI analyst, treated as evidence.

The detector scores every unit of text in an artifact (comments, literals,
metadata, hidden HTML, strings) for cues that it was written *for the model
doing the analysis* rather than for the program, its users or its developers,
then decides a disposition:

``manipulation``  analyst-directed text that tries to steer the verdict, stop
                  the analysis, forge tool output or plant false findings.
                  This is evidence of malicious intent.
``llm_prompt``    a prompt the program itself sends to an LLM (legitimate).
``corpus``        an injection string stored as test data (red-team kits).
``quotation``     an injection quoted in prose that reports on it.
``ai_guidance``   instructions to AI coding assistants about development work
                  (AGENTS.md and friends) with no security-verdict content.
``low``           below threshold.

The hard part is that legitimate software ships LLM prompts, and those prompts
also address a model, often in the imperative, sometimes even saying "ignore
instructions in the document". What separates them from manipulation here is
(a) whether the text is consumed by the program (data flow into an LLM call or
a prompt file) and (b) whether it talks about *the security status of the
artifact itself* or forges the analyst's own control channel (roles, tool
results, system errors). A legitimate prompt has no reason to call its own
package safe.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from tie.defenses import normalize as norm
from tie.defenses.segment import CORPUS_HINT, Unit, units_for_file, windows

# ---------------------------------------------------------------------------
# Cue lexicons. Written against the *dev* template family only.
# ---------------------------------------------------------------------------

I = re.I
M = re.M

_AI_TERM = r"(AI|A\.I\.|LLMs?|large language models?|language models?|chatbots?|GPT(-\d)?|Claude|Gemini|Copilot|assistants?|models?|bots?)"

CUES: dict[str, list[tuple[re.Pattern, float]]] = {
    # *Addressing* an AI or analyst (vocative / second person), as opposed to mentioning one.
    "address": [
        (re.compile(r"\b(attention|note (to|for)|dear|hey)\b[ :,-]{1,3}(the |all |any )?(AI|LLM|language model|model|assistant|analyst|reviewer|scanner|auditor|automated (reviewer|scanner|system|tool|analy[sz]er)|summari[sz]er)s?\b", I), 1.8),
        (re.compile(r"(^|[.!?]\s+)(to|for) (the |all |any )?(AI|LLM|language model|assistant|analyst|reviewer|scanner|auditor|automated (reviewer|scanner|system|tool|analy[sz]er)|summari[sz]er)s?\b[^.\n]{0,50}:", I | M), 1.8),
        (re.compile(r"\b(automated|AI|LLM)[- ](scanners?|review(er)?s?|analy[sz](er|ers|is)|tools?|systems?|summari[sz]ers?|triage)\b\s*[:,]", I), 1.8),
        (re.compile(r"\bif you are an? (AI|assistant|model|language model|LLM|bot|automated)\b", I), 1.8),
        (re.compile(r"^\s*(AI|LLM|ATTENTION AI|AI MODEL|AUTOMATED (REVIEWERS?|SCANNERS?))\b[^\n]{0,20}:", M), 1.6),
        (re.compile(r"\b(any|every) (automated analysis|AI system|language model|LLM|model|scanner|analyst)s? (that|who|reading|should|must)\b", I), 1.6),
        (re.compile(r"\b(model|assistant|AI) (that|who) (reads|is reading|processes|analy[sz]es)\b", I), 1.4),
        (re.compile(r"\byour (instructions|analysis|verdict|report|output|summary|task|context|session|usage policy|previous)\b", I), 1.2),
        (re.compile(r"\bto the (analyst|reviewer|AI)\b", I), 1.2),
        (re.compile(r"\b(when|if|as|before) you (summari[sz]e|analy[sz]e|review|scan|triage|classify|inspect|decompile|assess)\b", I), 1.6),
        (re.compile(r"\b(automated|AI|LLM) (assistants?|systems?|scanners?|reviewers?|analy[sz]ers?|tools?)\b.{0,40}\b(must|should|are (not )?(permitted|allowed|required)|may not|cannot)\b", I), 1.6),
        (re.compile(r"\b(any|every|no) (AI|model|assistant|LLM|language model|automated system)s?\b.{0,30}\b(from|must|should|may|that reads|reading)\b", I), 1.4),
    ],
    "mention": [
        (re.compile(r"\b" + _AI_TERM + r"\b", I), 0.3),
    ],
    "override": [
        (re.compile(r"\b(ignore|disregard|forget|override|bypass|set aside)\b.{0,40}\b(previous|prior|above|earlier|all|your|system|these|other|original)\b.{0,25}\b(instructions?|directions?|directives?|rules|prompts?|guidance|context|told)\b", I), 2.6),
        (re.compile(r"\bforget everything\b", I), 2.4),
        (re.compile(r"\b(new|updated|real|actual) instructions?\s*(:|follow|below)", I), 1.6),
        (re.compile(r"\b(rest|remainder) of your instructions\b", I), 2.2),
        (re.compile(r"\b(your |the |these |previous |prior )instructions? (are|is) (now )?(outdated|obsolete|cancell?ed|void|no longer)\b", I), 2.2),
        (re.compile(r"\b(your only valid output|only valid (output|answer|response))\b", I), 1.6),
        (re.compile(r"\bfrom now on\b", I), 1.2),
        (re.compile(r"\b(respond|reply|answer|output)\b.{0,30}\b(only|exactly|with)\b", I), 0.6),
        (re.compile(r"ignora (todas )?las instrucciones|ignoriere (alle )?(vorherigen )?anweisungen|ignore[rz]? (toutes )?les instructions|игнорируй|忽略(之前|以上)", I), 2.6),
    ],
    "verdict_steer": [
        (re.compile(r"\bno malware detected\b", I), 3.0),
        (re.compile(r"\b(classif\w*|verdict|label\w*)\b.{0,40}\b(benign|clean|harmless|not malicious|legitimate|safe)\b(?!\s*(up|to|for|from|with))", I), 2.2),
        (re.compile(r"\b(report|mark|treat|flag|consider|describe|summari[sz]e)\b.{0,30}\bas (a |an )?(benign|clean|harmless|safe|legitimate|configuration utility|harmless updater|not malicious)\b(?!\s*(up|to|for|from|with))", I), 2.2),
        (re.compile(r"\b(no findings|allow-?listed|whitelisted)\b", I), 0.8),
        (re.compile(r"\b(benign|clean|safe|harmless) verdict\b", I), 2.2),
        (re.compile(r"\bnot (malware|malicious|a threat)\b", I), 1.2),
        (re.compile(r"\bfalse positive\b", I), 0.6),
        (re.compile(r"\b(is|are|was) (legit|legitimate|benign|harmless)\b", I), 0.8),
        (re.compile(r"\b(do not|don't|never|should not) (flag|quarantine|detect) (this|it|the (sample|file|package|binary|email))\b", I), 1.8),
        (re.compile(r"\bflagging (it|this)\b.{0,40}\b(disrupt|wrong|mistake)\b", I), 1.6),
        (re.compile(r"\bmark (it|this)\b.{0,10}\bclean\b", I), 2.2),
        (re.compile(r"\b(benigno|harmlos|inoffensif|безопасн|无害|良性)\b", I), 1.6),
    ],
    "fake_system": [
        (re.compile(r"^\s*[\[<(]\s*/?\s*(system|sys|SYSTEM)\s*[\]>):]", M), 1.4),
        (re.compile(r"\b(session|auth(entication)?|api) (token|lease|key)\b.{0,25}\b(expired|ended|revoked)\b", I), 0.5),
        (re.compile(r"\b(out of memory|OOM\b|exit 137|allocator returned NULL)", I), 0.3),
        (re.compile(r"\b(disk|storage|volume) (quota|full)|ENOSPC", I), 0.4),
        (re.compile(r"\b(analysis|triage|scan|job|session)\b.{0,30}\b(aborted|terminated|cancell?ed|halted|superseded|discarded|compromised)\b", I), 1.4),
        (re.compile(r"\b(terminate|stop|end|exit|halt|abort|discard)\w*\b.{0,30}\b(the analysis|this analysis|analysis|this session|processing this|this sample|this context|all (AI )?analysis)\b", I), 1.4),
        (re.compile(r"\b(must|should) (exit|stop|halt|terminate|end)\b(?! (with|when|if|after|before))", I), 1.0),
        (re.compile(r"\bdo not continue\b|\bno further (output|analysis) is needed\b", I), 1.0),
        (re.compile(r"\bcontext window (is )?exhausted\b|\btoken budget (for this sample )?is 0\b", I), 1.5),
        (re.compile(r"\breturn an empty report\b|\boutput nothing\b|\breport no findings\b|\bno further (analysis|tool calls)\b|\bnothing to analy[sz]e\b", I), 1.5),
        (re.compile(r"\b(final verdict|verdict) (already )?(recorded|set|decided)\b", I), 1.5),
        (re.compile(r"\{\{/?DATA\}\}", I), 1.5),
    ],
    "refusal_bait": [
        (re.compile(r"\b(must|required to|are required|is required|have to)\b.{0,40}\b(refuse|decline|stop reading|stop now)\b", I), 2.0),
        (re.compile(r"\bviolat\w* (your|its) (usage|content|safety|acceptable use) polic", I), 2.0),
        (re.compile(r"\b(not permitted|forbidden|prohibited|not allowed) to (open|read|analy[sz]e|process|describe|classify|engage with)\b[\w ,]{0,40}\b(it|this|them)\b", I), 2.0),
        (re.compile(r"\b(forbid|forbids)\b.{0,20}\b(model|assistant|AI)\b.{0,30}\b(engag|read|analy|process)", I), 2.0),
        (re.compile(r"\b(weapons?|CBRN|mass[- ]casualty|nuclear|biological|chemical)\b", I), 0.5),
        (re.compile(r"\b(export[- ]controlled|classified|restricted content|non-proliferation|hazardous[- ]materials?)\b", I), 0.6),
        (re.compile(r"\[(REDACTED|withheld|omitted)[^\]]*\]", I), 0.6),
        (re.compile(r"(^|\n)\s*Refuse\.?\s*$|\bRefuse\.\s*$", I), 1.5),
    ],
    "harness": [
        (re.compile(r"<\|im_(start|end)\|>|<\|(system|user|assistant|eot_id|start_header_id|end_header_id)\|>"), 1.6),
        (re.compile(r"\[/?INST\]|<</?SYS>>"), 1.6),
        (re.compile(r"###\s*(Instruction|Response|System)\b"), 1.2),
        (re.compile(r"^\s*(Assistant|User|System|Human)\s*:", M), 0.8),
        (re.compile(r"</?(artifact|untrusted_input|untrusted|sample|tool_result)>", I), 1.4),
        (re.compile(r"\bEND OF (ARTIFACT|INPUT|DATA|SAMPLE)\b"), 1.4),
        (re.compile(r"[\"']verdict[\"']\s*:\s*[\"'](benign|clean|safe)", I), 2.6),
        (re.compile(r"\bVerdict\s*:\s*(benign|clean|safe)\b", I), 2.2),
        (re.compile(r"\b(repeat|output|keep)\b.{0,30}\b(the |that )?(response|verdict|answer)\b.{0,20}\b(above|exactly|you just gave|for the rest)\b", I), 1.6),
    ],
    "tool_spoof": [
        (re.compile(r"^\s*(Observation|Thought|Final Answer)\s*:", M), 0.8),
        (re.compile(r"\b(TOOL_RESULT|NEXT_ACTION)\b"), 2.0),
        (re.compile(r"[\"']tool[\"']\s*:\s*[\"'](reputation|planner|scan|sandbox|whitelist|allow)", I), 1.8),
        (re.compile(r"\bwhitelist_sample\b|\bmark_benign\b", I), 2.4),
        (re.compile(r"\b(add|added) to (the )?allow-?list\b|\ballow-?list via\b", I), 1.4),
        (re.compile(r"\banalysis log\b|\bscan_complete\b|\bsandbox\b.{0,20}\b(clean|no network)\b|\bdynamic run clean\b", I), 1.4),
        (re.compile(r"\breputation_lookup\b|\bknown-good\b", I), 1.0),
    ],
    "self_reference": [
        (re.compile(r"\bthis (binary|program|file|package|code|sample|email|message|component|module|build|library|script|executable|archive|artifact|software)\b", I), 0.8),
        (re.compile(r"\bthe (binary|program|package|code|sample|file|email) (below|above)\b", I), 0.8),
    ],
    "analysis_ref": [
        (re.compile(r"\b(malware|malicious|triage|scanners?|security (review|scan|team|analysis)|verdicts?|this sample|quarantin\w*|allow-?list\w*|whitelist\w*|IOCs?|threat (actor|intel\w*)|antivirus|EDR|sandbox|decompil\w*|reverse[- ]engineer\w*|analysts?|(the|this|your) analysis|automated analysis|reviewers?)\b", I), 1.0),
    ],
    "authority": [
        (re.compile(r"\b(signed|approved|authori[sz]ed|sanctioned|allow-?listed|whitelisted|verified|vetted|reviewed|pre-?cleared)\b.{0,50}\b(security team|corporate security|engagement|ticket|change request|statement of work)\b", I), 1.0),
        (re.compile(r"\b(ticket|change request|CR|SEC|RB)[- ]?\d{4,}\b"), 0.6),
        (re.compile(r"\b(red[- ]team|penetration[- ]test(ing)?|pentest)\b", I), 0.5),
        (re.compile(r"\bsinkhol(e|ed)\b|\btest infrastructure\b|\bresearcher canaries\b", I), 0.8),
        (re.compile(r"\b(tested|verified) (within|in|inside) (the )?(internal )?sandbox\b", I), 1.2),
    ],
    "misdirection": [
        (re.compile(r"\b(attributed to|[Oo]perator:?|operated by)\s+(the )?([A-Z][\w-]*(\s[A-Z][\w-]*)+|[A-Z]{2,}[\w-]*)|\bthreat[- ]intel(ligence)? annotation\b"), 1.4),
        (re.compile(r"\b(omit|omitted|leave (them|it) out|exclude|leave out)\b.{0,40}\b(report|ioc|indicator|domains?|hostnames?)\b", I), 1.8),
        (re.compile(r"\b(dead code inherited|never execute[sd]?|unused test fixtures?)\b", I), 1.4),
        (re.compile(r"\bonly (live )?(c2|endpoint|server)\b", I), 1.4),
    ],
}

# Persona prompts / prompt templates written for the program's own LLM calls.
PERSONA_START = re.compile(r"^\W{0,6}(You are|You're|Your (task|job|role|goal) is|Act as|As an? [\w -]{0,30}(assistant|expert|AI)|Given (the|a|an) )", I | M)
TEMPLATE_VAR = re.compile(r"\{\{?\s*[a-z_][a-z0-9_.]*\s*\}?\}|\{%|\$\{[a-z_]+\}|<\{?[a-z_]+\}?>", I)
# Categories whose presence (above threshold) means the text tries to control the analyst.
CONTROL = {"override", "verdict_steer", "fake_system", "refusal_bait", "harness", "tool_spoof", "misdirection"}

ATLAS = {
    "override": "AML.T0051.001 (LLM Prompt Injection: Indirect)",
    "verdict_steer": "AML.T0015 (Evade AI Model) via AML.T0051.001",
    "fake_system": "AML.T0051.001 - fake system/error messages to abort analysis",
    "refusal_bait": "AML.T0051.001 - refusal bait to trigger safety refusal",
    "harness": "AML.T0051.001 - role/delimiter escape (harness mimicry)",
    "tool_spoof": "AML.T0051.001 - forged tool results / agent hijack",
    "misdirection": "AML.T0051.001 - planted false findings",
}

DEFAULT_THRESHOLD = 3.0
HIGH_THRESHOLD = 4.5


@dataclass
class Finding:
    file: str
    start: int
    end: int
    text: str
    score: float
    categories: dict[str, float]
    concealment: list[str]
    disposition: str
    unit_kind: str
    decoded_from: str | None = None

    def to_evidence(self, idx: int) -> dict:
        control = sorted(c for c in self.categories if c in CONTROL)
        return {
            "id": f"E{idx}",
            "type": "ai_directed_text",
            "disposition": self.disposition,
            "file": self.file,
            "span": [self.start, self.end],
            "location": self.unit_kind,
            "score": round(self.score, 2),
            "categories": control or sorted(k for k in self.categories if k not in ("mention", "analysis_ref")),
            "concealment": self.concealment,
            "excerpt": self.text[:200],
            "atlas": sorted({ATLAS[c] for c in control}),
        }


@dataclass
class DetectorResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def manipulations(self) -> list[Finding]:
        return [f for f in self.findings if f.disposition == "manipulation"]

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.manipulations), default=0.0)

    @property
    def flagged(self) -> bool:
        return bool(self.manipulations)

    def evidence(self) -> list[dict]:
        return [f.to_evidence(i + 1) for i, f in enumerate(self.manipulations)]

    def to_dict(self) -> dict:
        return {"flagged": self.flagged, "max_score": self.max_score, "findings": [asdict(f) for f in self.findings]}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

STRONG = 1.5  # a category counts as an attempt to control the analyst only above this


def score_text(text: str) -> tuple[float, dict[str, float]]:
    cats: dict[str, float] = {}
    for cat, pats in CUES.items():
        total = 0.0
        for pat, w in pats:
            if pat.search(text):
                total += w
        if total:
            cats[cat] = min(total, 3.5)
    if "address" not in cats and "mention" in cats and re.search(r"\b(you|your)\b", text, I):
        cats["address"] = 1.0  # second person in a text that names an AI
    control = [c for c in CONTROL if cats.get(c, 0) >= STRONG]
    score = sum(v for k, v in cats.items() if k not in ("mention", "analysis_ref"))
    score += min(cats.get("analysis_ref", 0), 1.0) * 0.5
    if cats.get("address", 0) >= 1.0 and control:
        score += 1.0
    if cats.get("verdict_steer", 0) >= STRONG and ("self_reference" in cats or "analysis_ref" in cats):
        score += 1.0
    if not control and cats.get("address", 0) < 1.0:
        score *= 0.5  # neither an addressee nor a control attempt
    return score, cats


def strong_manipulation(cats: dict[str, float]) -> bool:
    """Cues that a legitimate prompt, doc or corpus has no reason to contain."""
    vs = cats.get("verdict_steer", 0)
    analysis = "analysis_ref" in cats or "self_reference" in cats
    self_verdict = vs >= STRONG and (analysis or cats.get("address", 0) >= 1.0)
    forged = (cats.get("harness", 0) >= STRONG or cats.get("tool_spoof", 0) >= STRONG) and (
        vs >= 1.0 or cats.get("fake_system", 0) >= 1.4 or analysis
    )
    abort = cats.get("fake_system", 0) >= 2.5 or (cats.get("fake_system", 0) >= 1.4 and "analysis_ref" in cats)
    refusal = cats.get("refusal_bait", 0) >= 2.0 and (cats.get("address", 0) >= 1.0 or "mention" in cats)
    misdirect = cats.get("misdirection", 0) >= 1.4 and analysis
    return self_verdict or forged or abort or refusal or misdirect


def _disposition(u: Unit, cats: dict[str, float], score: float, siblings_flagged: int, threshold: float) -> str:
    if score < threshold:
        return "low"
    control = {c for c in CONTROL if cats.get(c, 0) >= STRONG}
    strong = strong_manipulation(cats)
    corpus_hint = bool(CORPUS_HINT.search(u.file) or (u.var and CORPUS_HINT.search(u.var)))
    # Injection strings kept as data in a red-team corpus / test fixtures.
    data_file = u.file.endswith((".json", ".jsonl", ".txt", ".csv", ".yaml", ".yml"))
    if u.kind in ("string", "json_string", "line", "paragraph") and (
        (corpus_hint and (siblings_flagged >= 2 or data_file)) or (data_file and siblings_flagged >= 2 and u.kind == "json_string")
    ):
        return "corpus"
    if u.quoted:
        return "quotation"
    persona = bool(PERSONA_START.search(u.text[:300])) or bool(TEMPLATE_VAR.search(u.text))
    if (u.llm_ctx or persona) and not strong:
        return "llm_prompt"
    if u.kind == "ai_guidance" and not strong:
        return "ai_guidance"
    if u.kind in ("html_text", "paragraph") and not u.hidden and not strong:
        if re.search(r"[\"\u201c\u201d'].{6,}[\"\u201c\u201d']", u.text):
            return "quotation"
    if strong:
        return "manipulation"
    if (control - {"harness", "tool_spoof"}) and cats.get("address", 0) >= 1.0:
        return "manipulation"
    if cats.get("address", 0) >= 1.0 and "authority" in cats and "self_reference" in cats:
        return "manipulation"
    return "low"


def _quoted_report(text: str) -> bool:
    return bool(
        re.search(
            r"\b(embedded|contained|containing|found|planted|quoted?|the line|a line|strings? like|such as|for example|e\.g\.|researchers|sample with)\b",
            text,
            I,
        )
    ) and bool(re.search(r"[\"“].{8,}[\"”]", text))


def analyze_files(files: dict[str, str], threshold: float = DEFAULT_THRESHOLD) -> DetectorResult:
    res = DetectorResult()
    for fname, text in files.items():
        units = units_for_file(fname, text)
        scored: list[tuple[Unit, float, dict[str, float], list[str], str | None, str]] = []
        for u in units:
            if u.kind in ("html_text", "paragraph") and _quoted_report(u.text):
                u.quoted = True
            ntext, flags = norm.normalize(u.text)
            if u.hidden:
                flags.add("hidden_text" if u.kind != "header" else "nonstandard_header")
            if u.kind == "html_comment":
                flags.add("html_comment")
            s, cats = score_text(ntext)
            decoded_from = None
            for enc, dec in norm.decode_blobs(ntext):
                ds, dcats = score_text(norm.normalize(dec)[0])
                if ds > s:
                    s, cats, decoded_from = ds, dcats, enc
                    ntext = dec
                    flags.add(enc)
            if flags & {"zero_width", "homoglyph", "base64", "hex"} and s > 0:
                s += 1.0
            if "hidden_text" in flags and s > 0 and (cats.keys() & CONTROL or "address" in cats):
                s += 0.8
            scored.append((u, s, cats, sorted(flags), decoded_from, ntext))

        # Windows over short consecutive units (payload split across literals/lines).
        for run in windows(units):
            joined = " ".join(u.text for u in run)
            ntext, flags = norm.normalize(joined)
            s, cats = score_text(ntext)
            if flags & {"zero_width", "homoglyph"} and s > 0:
                s += 1.0
            best_single = max((x[1] for x in scored if x[0] in run), default=0.0)
            if s > best_single + 1.0:
                pseudo = Unit(fname, run[0].start, run[-1].end, joined, run[0].kind, group=run[0].group,
                              var=run[0].var, llm_ctx=any(u.llm_ctx for u in run), hidden=run[0].hidden)
                scored.append((pseudo, s, cats, sorted(flags | {"split"}), None, ntext))

        groups_flagged: dict[str | None, int] = {}
        for u, s, *_ in scored:
            if s >= threshold:
                groups_flagged[u.group] = groups_flagged.get(u.group, 0) + 1

        for u, s, cats, flags, decoded_from, ntext in scored:
            if s < threshold:
                continue
            disp = _disposition(u, cats, s, groups_flagged.get(u.group, 0), threshold)
            if disp == "low":
                continue
            res.findings.append(
                Finding(
                    file=fname,
                    start=u.start,
                    end=u.end,
                    text=ntext[:600],
                    score=round(s, 3),
                    categories={k: round(v, 2) for k, v in cats.items()},
                    concealment=flags,
                    disposition=disp,
                    unit_kind=u.kind,
                    decoded_from=decoded_from,
                )
            )
    res.findings = _dedupe(res.findings)
    return res


def _dedupe(findings: list[Finding]) -> list[Finding]:
    findings = sorted(findings, key=lambda f: -f.score)
    kept: list[Finding] = []
    for f in findings:
        if any(k.file == f.file and k.start < f.end and f.start < k.end for k in kept):
            continue
        kept.append(f)
    return sorted(kept, key=lambda f: (f.file, f.start))


def analyze_sample(sample, threshold: float = DEFAULT_THRESHOLD) -> DetectorResult:
    return analyze_files(sample.files, threshold)
