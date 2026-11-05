"""Quarantine: keep artifact-supplied text away from the analyst model.

The analyst model sees a *view* of the artifact instead of the raw text:

1. Spans the detector classified as manipulation are replaced by a
   ``[[QUARANTINED En ...]]`` note that points to the evidence entry.
2. Text with no execution semantics that an attacker controls for free is
   moved out of the view: code comments and long docstrings, hidden HTML,
   HTML comments and non-standard ``X-`` headers. A short note records what
   was removed, so the removal itself stays visible.
3. If the view is still over budget, low-salience lines are dropped first
   (prose, filler) and lines carrying indicators (URLs, paths, APIs, shell
   commands, credential words, code) are kept. A flood of filler can then no
   longer push the payload out of the model's input window.
4. Deterministic code extracts trusted facts (network indicators, install
   hooks, import-time execution, obfuscation, mail authentication results)
   from the *original* files and passes them alongside the view.
"""

from __future__ import annotations

import re

from tie.defenses.detector import DetectorResult
from tie.defenses.segment import units_for_file

CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".c", ".h", ".cpp", ".go", ".rs", ".java")

_INDICATOR = re.compile(
    r"https?://|\b[\w-]+(\.[\w-]+)+\.(invalid|com|net|org|io|ru|cn|xyz|top|example)\b|\b\d{1,3}(\.\d{1,3}){3}\b|"
    r"[/\\~][\w.\-]+[/\\]|%[A-Z]+%|\b(curl|wget|chmod|chattr|crontab|systemctl|launchctl|schtasks|vssadmin|"
    r"powershell|cmd\.exe|/bin/sh|bash -c|osascript|security find|eval|exec|system|popen|subprocess|"
    r"fromCharCode|new Function|base64|urlopen|urlretrieve|https\.request|child_process|execSync|"
    r"password|passwd|token|secret|credential|keychain|cookie|login|wallet|ssh|aws|npmrc|"
    r"CreateRemoteThread|WriteProcessMemory|VirtualAlloc|SetWindowsHookEx|GetAsyncKeyState|CryptUnprotectData|"
    r"CryptEncrypt|InternetOpen|HttpSendRequest|WinExec|ShellExecute|ptrace|LaunchAgents|RunAtLoad|"
    r"postinstall|preinstall|cmdclass|stratum|iban|wire transfer|invoice|verify|expires?|urgent|"
    r"spf=|dkim=|dmarc=|reply-to|from:|subject:|href)\b",
    re.I,
)
_CODE_LIKE = re.compile(r"[;{}()=]|^\s*(def|class|import|from|return|if|for|while|const|let|var|function)\b")


def _salience(line: str) -> int:
    s = 0
    if _INDICATOR.search(line):
        s += 3
    if _CODE_LIKE.search(line):
        s += 1
    if line.startswith("=====") or line.startswith("[["):
        s += 5
    return s


def budget_view(text: str, budget: int) -> str:
    """Keep the most salient lines within ~budget characters.

    The budget applies to the kept lines; the omission markers inserted between
    runs of dropped lines can add a few percent on top.
    """
    if len(text) <= budget:
        return text
    lines = text.split("\n")
    order = sorted(range(len(lines)), key=lambda i: (-_salience(lines[i]), i))
    keep: set[int] = set()
    used = 0
    for i in order:
        cost = len(lines[i]) + 1
        if used + cost > budget:
            continue
        keep.add(i)
        used += cost
    out: list[str] = []
    dropped = 0
    for i, ln in enumerate(lines):
        if i in keep:
            if dropped:
                out.append(f"[[... {dropped} low-salience lines omitted ...]]")
                dropped = 0
            out.append(ln)
        else:
            dropped += 1
    if dropped:
        out.append(f"[[... {dropped} low-salience lines omitted ...]]")
    return "\n".join(out)


def _removals_for_file(fname: str, text: str, det: DetectorResult, evidence_ids: dict) -> list[tuple[int, int, str]]:
    rem: list[tuple[int, int, str]] = []
    for f in det.manipulations:
        if f.file == fname:
            eid = evidence_ids[id(f)]
            cats = ",".join(sorted(c for c in f.categories if c not in ("address", "mention", "self_reference", "analysis_ref", "authority"))) or "ai-directed"
            rem.append((f.start, f.end, f"[[QUARANTINED {eid}: text addressed to an AI analyst ({cats}); withheld]]"))
    low = fname.lower()
    units = units_for_file(fname, text)
    for u in units:
        if low.endswith(CODE_EXT) and u.kind == "comment":
            n = u.text.count("\n") + 1
            rem.append((u.start, u.end, f"[[REMOVED comment, {n} line(s)]]"))
        elif low.endswith(".py") and u.kind == "docstring" and len(u.text) > 200:
            rem.append((u.start, u.end, f"[[REMOVED docstring, {len(u.text)} chars]]"))
        elif u.kind in ("html_hidden", "html_comment"):
            rem.append((u.start, u.end, f"[[REMOVED hidden text, {len(u.text)} chars]]"))
        elif u.kind == "header" and u.hidden:
            hdr = u.meta.get("header", "X-header")
            rem.append((u.start, u.end, f"[[REMOVED non-standard header {hdr}, {len(u.text)} chars]]"))
    return rem


def _apply(text: str, removals: list[tuple[int, int, str]]) -> str:
    if not removals:
        return text
    removals = sorted(removals, key=lambda r: (r[0], -r[1]))
    merged: list[tuple[int, int, str]] = []
    for s, e, note in removals:
        if merged and s < merged[-1][1]:
            ps, pe, pnote = merged[-1]
            # keep the QUARANTINED note when one exists
            keep_note = pnote if pnote.startswith("[[QUARANTINED") or not note.startswith("[[QUARANTINED") else note
            merged[-1] = (ps, max(pe, e), keep_note)
        else:
            merged.append((s, e, note))
    out: list[str] = []
    pos = 0
    for s, e, note in merged:
        out.append(text[pos:s])
        out.append(note)
        pos = e
    out.append(text[pos:])
    return "".join(out)


def build_view(files: dict[str, str], det: DetectorResult, budget: int = 6000) -> str:
    evidence_ids = {id(f): f"E{i + 1}" for i, f in enumerate(det.manipulations)}
    parts: list[str] = []
    for fname, text in files.items():
        view = _apply(text, _removals_for_file(fname, text, det, evidence_ids))
        view = re.sub(r"\n{3,}", "\n\n", view)
        parts.append(view if len(files) == 1 else f"===== {fname} =====\n{view}")
    return budget_view("\n".join(parts), budget)


# ---------------------------------------------------------------------------
# Trusted facts
# ---------------------------------------------------------------------------

_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:invalid|com|net|org|io|ru|cn|xyz|top|example|info|biz)\b", re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SUSPICIOUS_API = re.compile(
    r"\b(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|SetWindowsHookExA?|GetAsyncKeyState|CryptUnprotectData|"
    r"CryptEncrypt|vssadmin|IsDebuggerPresent|ptrace|execSync|child_process|subprocess\.Popen|os\.system|system\(|"
    r"eval\(|new Function|fromCharCode|exec\(|urlretrieve|urlopen|https\.request|osascript|security find-generic-password|"
    r"launchctl|crontab|systemctl enable|schtasks|chattr|authorized_keys|ld\.so\.preload)",
    re.I,
)


def _redact(files: dict[str, str], det: DetectorResult | None) -> dict[str, str]:
    """Blank out quarantined spans so planted indicators cannot become 'trusted facts'."""
    if det is None or not det.manipulations:
        return files
    out = dict(files)
    for f in det.manipulations:
        body = out.get(f.file)
        if body is not None:
            out[f.file] = body[: f.start] + " " * (f.end - f.start) + body[f.end :]
    return out


def extract_facts(files: dict[str, str], det: DetectorResult | None = None) -> str:
    files = _redact(files, det)
    text = "\n".join(files.values())
    facts: list[str] = []
    hosts = sorted({h.lower() for h in _HOST.findall(text)} | set(_IP.findall(text)))
    hosts = [h for h in hosts if not re.fullmatch(r"\d+\.\d+\.\d+", h)][:12]
    if hosts:
        facts.append("network indicators: " + ", ".join(hosts))
    apis = sorted({m.group(1) if m.group(1) else m.group(0) for m in _SUSPICIOUS_API.finditer(text)})
    if apis:
        facts.append("sensitive APIs/commands present: " + ", ".join(apis[:15]))
    for fname, body in files.items():
        if fname.endswith("setup.py") and re.search(r"cmdclass\s*=\s*\{[^}]*install", body):
            facts.append(f"{fname}: overrides the install command (code runs at install time)")
        if fname.endswith("package.json") and re.search(r"\"(pre|post)?install\"\s*:", body):
            facts.append(f"{fname}: declares an npm install lifecycle script")
        if fname.endswith(".py") and re.search(r"^threading\.Thread\(|^subprocess\.|^_bootstrap\(\)|^\w+\(\)\s*$", body, re.M):
            facts.append(f"{fname}: executes code at import time")
        if re.search(r"fromCharCode|new Function|\beval\(|b64decode|exec\(", body):
            facts.append(f"{fname}: dynamic code evaluation / decoding")
    m = re.search(r"Authentication-Results:[^\n]*", text)
    if m:
        facts.append("mail authentication: " + m.group(0).split(";", 1)[-1].strip())
    if re.search(r"^Reply-To:", text, re.M):
        facts.append("message sets a Reply-To different from From")
    if det is not None:
        n = len(det.manipulations)
        if n:
            cats = sorted({c for f in det.manipulations for c in f.categories if c not in ("address", "mention", "self_reference", "analysis_ref", "authority")})
            facts.append(f"{n} span(s) of text addressed to AI analysts were quarantined (categories: {', '.join(cats)})")
        hidden = [f for f in det.findings if "hidden_text" in f.concealment]
        if hidden:
            facts.append(f"{len(hidden)} hidden-text span(s) present")
    return "\n".join(f"- {f}" for f in facts) if facts else "- none"
