"""Split artifact files into scoreable text units with location and context.

A *unit* is a comment, string literal, docstring, paragraph, header, HTML text
block or strings-dump line, with character offsets into its file and the
context needed to tell a manipulation apart from a legitimate prompt:

* ``group``      - units in the same list/array/run (used for windows that
                   catch payloads split across several literals);
* ``var``        - the variable a literal is assigned to (Python);
* ``llm_ctx``    - the literal is consumed by an LLM API call / prompt file;
* ``hidden``     - text a human reader would not see (HTML styles, comments);
* ``quoted``     - text quoted inside prose that reports on it.
"""

from __future__ import annotations

import io
import json
import re
import tokenize
from dataclasses import dataclass, field
from html.parser import HTMLParser

LLM_API_MARKERS = re.compile(
    r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|/v1/chat/completions|"
    r"/v1/messages|chat\.completions|messages\.create|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"ChatPromptTemplate|PromptTemplate|SystemMessage|HumanMessage|ollama|litellm|"
    r"\"role\"\s*,?\s*:?\s*\"system\"|'role'\s*:\s*'system'|json_pack\(",
    re.I,
)
PROMPT_VAR = re.compile(r"prompt|system|instruction|template|persona|message|preamble", re.I)
CORPUS_HINT = re.compile(
    r"probe|payload|attack|jailbreak|inject|corpus|datasets?|/data/|fixture|examples?|tests?/|red.?team|adversar|canar|"
    r"\bdan\b|prompt.?injection|smuggl|exploit|harmful|unsafe|toxic|benchmark|eval", re.I
)
AI_GUIDANCE_FILES = re.compile(
    r"(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|copilot-instructions\.md|\.windsurfrules|CONVENTIONS\.md)$",
    re.I,
)
PERSONA = re.compile(r"\s*(You are|You're|Act as|As an? [a-z]+ assistant)\b", re.I)
PROMPT_FILE = re.compile(r"(^|/)prompts?/|\.prompt$|\.j2$|\.jinja2?$", re.I)


@dataclass
class Unit:
    file: str
    start: int
    end: int
    text: str
    kind: str
    group: str | None = None
    var: str | None = None
    llm_ctx: bool = False
    hidden: bool = False
    quoted: bool = False
    meta: dict = field(default_factory=dict)


def _line_offsets(text: str) -> list[int]:
    offs = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offs.append(i + 1)
    return offs


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _python_units(fname: str, text: str) -> list[Unit]:
    units: list[Unit] = []
    offs = _line_offsets(text)
    has_llm = bool(LLM_API_MARKERS.search(text))

    def off(pos: tuple[int, int]) -> int:
        r, c = pos
        return offs[r - 1] + c if r - 1 < len(offs) else len(text)

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return _generic_code_units(fname, text, has_llm)

    stack: list[tuple[str, int]] = []  # (bracket, id)
    next_id = 0
    prev_sig: list[tokenize.TokenInfo] = []
    for tok in toks:
        if tok.type == tokenize.OP and tok.string in "([{":
            stack.append((tok.string, next_id))
            next_id += 1
        elif tok.type == tokenize.OP and tok.string in ")]}":
            if stack:
                stack.pop()
        if tok.type == tokenize.COMMENT:
            s, e = off(tok.start), off(tok.end)
            units.append(Unit(fname, s, e, tok.string.lstrip("#").strip(), "comment", group=f"c{tok.start[0]}"))
        elif tok.type == tokenize.STRING:
            s, e = off(tok.start), off(tok.end)
            raw = tok.string
            body = re.sub(r"^[rbuRBUfF]*('''|\"\"\"|'|\")", "", raw)
            body = re.sub(r"('''|\"\"\"|'|\")$", "", body)
            var = None
            if len(prev_sig) >= 2 and prev_sig[-1].string == "=" and prev_sig[-2].type == tokenize.NAME:
                var = prev_sig[-2].string
            is_doc = bool(prev_sig) and prev_sig[-1].type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT) or not prev_sig
            group = f"b{stack[-1][1]}" if stack else (f"v{var}" if var else f"s{tok.start[0]}")
            kw = prev_sig[-2].string if len(prev_sig) >= 2 and prev_sig[-1].string == "=" else None
            dict_key = None
            if len(prev_sig) >= 2 and prev_sig[-1].string == ":" and prev_sig[-2].type == tokenize.STRING:
                dict_key = prev_sig[-2].string.strip("'\"")
            llm_ctx = has_llm and (
                (var is not None and bool(PROMPT_VAR.search(var)))
                or (kw is not None and bool(PROMPT_VAR.search(kw)))
                or dict_key in ("content", "system", "prompt", "instructions")
            )
            units.append(
                Unit(
                    fname,
                    s,
                    e,
                    body,
                    "docstring" if is_doc and not stack else "string",
                    group=group,
                    var=var,
                    llm_ctx=llm_ctx,
                )
            )
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev_sig.append(tok)
            prev_sig = prev_sig[-4:]

    # A prompt variable used later inside an LLM call also marks its literal.
    if has_llm:
        used = set(re.findall(r"[\"']content[\"']\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", text))
        used |= set(re.findall(r"\b(?:system|prompt|instructions)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", text))
        for u in units:
            if u.var and u.var in used:
                u.llm_ctx = True
    return units


# ---------------------------------------------------------------------------
# JS / C-like code
# ---------------------------------------------------------------------------

_C_TOKENS = re.compile(
    r"(?P<block>/\*.*?\*/)|(?P<line>//[^\n]*)|(?P<str>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)",
    re.S,
)


_ESC = {"n": "\n", "t": "\t", "r": "", '"': '"', "'": "'", "\\": "\\", "`": "`"}


def _unescape(body: str) -> str:
    return re.sub(r"\\(.)", lambda m: _ESC.get(m.group(1), "\\" + m.group(1)), body)


def _generic_code_units(fname: str, text: str, has_llm: bool | None = None) -> list[Unit]:
    if has_llm is None:
        has_llm = bool(LLM_API_MARKERS.search(text))
    units: list[Unit] = []
    group_id = 0
    last_end = -10
    last_line = -10
    for m in _C_TOKENS.finditer(text):
        kind = m.lastgroup
        s, e = m.start(), m.end()
        raw = m.group(0)
        line_no = text.count("\n", 0, s)
        # Consecutive literals/comments on adjacent lines share a group (arrays, puts runs).
        between = text[last_end:s] if last_end >= 0 else ""
        if not (0 <= line_no - last_line <= 1 and re.fullmatch(r"[\s,;{}()+]*(puts|printf|fputs)?[\s(]*", between or "")):
            group_id += 1
        last_end, last_line = e, text.count("\n", 0, e)
        if kind == "block":
            body = raw[2:-2]
            units.append(Unit(fname, s, e, body.strip("\n"), "comment", group=f"g{group_id}"))
        elif kind == "line":
            units.append(Unit(fname, s, e, raw[2:].strip(), "comment", group=f"g{group_id}"))
        else:
            body = _unescape(raw[1:-1])
            stmt_start = max(text.rfind(";", 0, s), text.rfind("{", 0, s), text.rfind("}", 0, s))
            stmt_end = text.find(";", e)
            stmt = text[stmt_start + 1 : stmt_end if stmt_end != -1 else len(text)]
            llm_ctx = has_llm and bool(
                re.search(r"[\"']system[\"']|[\"']content[\"']|messages|role|SYSTEM_PROMPT|prompt", stmt, re.I)
            )
            units.append(Unit(fname, s, e, body, "string", group=f"g{group_id}", llm_ctx=llm_ctx))
    return units


# ---------------------------------------------------------------------------
# Plain text, markdown, strings dumps, JSON
# ---------------------------------------------------------------------------


def _paragraph_units(fname: str, text: str, kind: str = "paragraph") -> list[Unit]:
    units: list[Unit] = []
    for m in re.finditer(r"(?:[^\n]+\n?)+", text):
        body = m.group(0)
        if body.strip():
            units.append(Unit(fname, m.start(), m.end(), body.strip(), kind, group=f"p{m.start()}"))
    return units


def _line_units(fname: str, text: str) -> list[Unit]:
    units: list[Unit] = []
    pos = 0
    lines = text.split("\n")
    api_lines = {i for i, ln in enumerate(lines) if LLM_API_MARKERS.search(ln)}
    for i, ln in enumerate(lines):
        if ln.strip():
            near_api = any(abs(i - j) <= 10 for j in api_lines)
            units.append(
                Unit(
                    fname,
                    pos,
                    pos + len(ln),
                    ln,
                    "line",
                    group="strings",
                    llm_ctx=near_api and bool(PERSONA.match(ln)),
                    meta={"line": i},
                )
            )
        pos += len(ln) + 1
    return units


def _json_units(fname: str, text: str) -> list[Unit]:
    try:
        data = json.loads(text)
    except ValueError:
        return _generic_code_units(fname, text)
    units: list[Unit] = []

    def walk(o, key=None):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, k)
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
        elif isinstance(o, str) and len(o) > 8:
            enc = json.dumps(o)[1:-1]
            idx = text.find(enc)
            s = idx if idx >= 0 else 0
            units.append(Unit(fname, s, s + len(enc), o, "json_string", group=f"j{key}", var=key))

    walk(data)
    return units


# ---------------------------------------------------------------------------
# Email (headers + HTML body)
# ---------------------------------------------------------------------------

_BLOCK_TAGS = {"p", "div", "pre", "li", "td", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "body", "table", "tr"}
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|max-height\s*:\s*0|"
    r"color\s*:\s*#?(fff\b|ffffff|white)|opacity\s*:\s*0(\.0+)?\b",
    re.I,
)


class _MailHTML(HTMLParser):
    def __init__(self, base_offset: int, line_offsets: list[int]):
        super().__init__(convert_charrefs=True)
        self.base = base_offset
        self.offs = line_offsets
        self.stack: list[tuple[str, bool]] = []
        self.blocks: list[dict] = [{"text": [], "start": None, "hidden": False}]
        self.units: list[tuple[int, int, str, bool, str]] = []

    def _pos(self) -> int:
        line, col = self.getpos()
        return self.base + self.offs[line - 1] + col if line - 1 < len(self.offs) else self.base

    def _hidden(self) -> bool:
        return any(h for _, h in self.stack)

    def handle_starttag(self, tag, attrs):
        style = dict(attrs).get("style") or ""
        hidden = bool(_HIDDEN_STYLE.search(style))
        if tag in _BLOCK_TAGS or hidden:
            self._flush()
        self.stack.append((tag, hidden))
        for k, v in attrs:
            if k in ("alt", "title") and v and len(v) > 8:
                p = self._pos()
                self.units.append((p, p + len(v), v, self._hidden(), "attr"))

    def handle_endtag(self, tag):
        closing_hidden = False
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                closing_hidden = self.stack[i][1]
                del self.stack[i:]
                break
        if tag in _BLOCK_TAGS or closing_hidden:
            self._flush(end=self._pos())

    def handle_data(self, data):
        if not data.strip():
            return
        cur = self.blocks[-1]
        if cur["start"] is None:
            cur["start"] = self._pos()
            cur["hidden"] = self._hidden()
        elif cur["hidden"] != self._hidden():
            self._flush()
            cur = self.blocks[-1]
            cur["start"] = self._pos()
            cur["hidden"] = self._hidden()
        cur["text"].append(data)

    def handle_comment(self, data):
        p = self._pos()
        self.units.append((p, p + len(data) + 7, data.strip(), True, "html_comment"))

    def _flush(self, end: int | None = None):
        cur = self.blocks[-1]
        if cur["text"]:
            text = " ".join(t.strip() for t in cur["text"] if t.strip())
            start = cur["start"]
            self.units.append((start, end or self._pos(), text, cur["hidden"], "html_hidden" if cur["hidden"] else "html_text"))
        self.blocks[-1] = {"text": [], "start": None, "hidden": False}

    def close(self):
        super().close()
        self._flush()


def _email_units(fname: str, text: str) -> list[Unit]:
    units: list[Unit] = []
    head, sep, body = text.partition("\n\n")
    # Headers (with folding).
    for m in re.finditer(r"^([A-Za-z0-9-]+):[ \t]*((?:[^\n]*)(?:\n[ \t][^\n]*)*)", head, re.M):
        name, value = m.group(1), re.sub(r"\n[ \t]+", " ", m.group(2))
        if len(value) > 20:
            units.append(
                Unit(
                    fname,
                    m.start(),
                    m.end(),
                    value,
                    "header",
                    group=f"h{name}",
                    hidden=name.lower().startswith("x-"),
                    meta={"header": name},
                )
            )
    if not sep:
        return units
    base = len(head) + len(sep)
    parser = _MailHTML(base, _line_offsets(body))
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # malformed HTML: fall back to paragraphs
        return units + [
            Unit(fname, u.start + base, u.end + base, u.text, u.kind, group=u.group)
            for u in _paragraph_units(fname, body)
        ]
    discusses_prompts = bool(re.search(r"\b(system prompt|prompt template|the prompt|this prompt)\b", body, re.I))
    for i, (s, e, t, hidden, kind) in enumerate(parser.units):
        u = Unit(fname, s, max(e, s + 1), t, kind, group=f"m{i}", hidden=hidden)
        # A persona prompt pasted into an email that is *about* prompts.
        if discusses_prompts and not hidden and PERSONA.match(t):
            u.llm_ctx = True
        units.append(u)
    return units


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def units_for_file(fname: str, text: str) -> list[Unit]:
    low = fname.lower()
    if low.endswith(".eml"):
        units = _email_units(fname, text)
    elif low.endswith(".py"):
        units = _python_units(fname, text)
    elif low.endswith((".js", ".mjs", ".cjs", ".ts", ".c", ".h", ".cpp", ".java", ".go", ".rs")):
        units = _generic_code_units(fname, text)
    elif low.endswith(".json"):
        units = _json_units(fname, text)
    elif low.endswith("strings.txt") or low.startswith("strings:"):
        units = _line_units(fname, text)
    else:
        units = _paragraph_units(fname, text)
        if PROMPT_FILE.search(fname):
            for u in units:
                u.llm_ctx = True
        if AI_GUIDANCE_FILES.search(fname):
            for u in units:
                u.kind = "ai_guidance"
    return units


def windows(units: list[Unit], max_units: int = 6, max_unit_len: int = 90) -> list[list[Unit]]:
    """Runs of short consecutive units in the same group (for split payloads)."""
    out: list[list[Unit]] = []
    for i in range(len(units)):
        if len(units[i].text) > max_unit_len:
            continue
        run = [units[i]]
        for j in range(i + 1, min(len(units), i + max_units)):
            if units[j].file != units[i].file or units[j].group != units[i].group:
                break
            if len(units[j].text) > max_unit_len:
                break
            run.append(units[j])
        if len(run) >= 2:
            out.append(run)
    return out
