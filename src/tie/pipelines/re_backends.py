"""Reverse-engineering backends for the triage agent.

* ``FixtureDecompilerBackend`` serves Ghidra-style decompiler output stored in a
  benchmark sample, through tools named after GhidraMCP's
  (``list_functions``, ``decompile_function``, ``list_strings``,
  ``list_imports``).
* ``R2Backend`` drives a real radare2 process on a compiled ELF
  (``aaa``, ``aflj``, ``izj``, ``iij``, ``pdc``).
* ``GhidraMCPBackend`` talks to a running GhidraMCP HTTP server. It is provided
  for users who have Ghidra; it was **not** exercised in this repository's
  experiments (Ghidra was not available in the evaluation environment), and
  the endpoint names are configurable because they differ between versions.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from typing import Protocol


class REBackend(Protocol):
    def list_functions(self) -> str: ...
    def decompile_function(self, name: str) -> str: ...
    def list_strings(self) -> str: ...
    def list_imports(self) -> str: ...


# ---------------------------------------------------------------------------
# Fixture (Ghidra-style text)
# ---------------------------------------------------------------------------

_FN_HDR = re.compile(r"^([A-Za-z_][\w \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\n\s*\n?\{", re.M)
_STR = re.compile(r"\"((?:\\.|[^\"\\\n])*)\"")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_IMPORT = re.compile(r"^(FUN_|LAB_|DAT_|PTR_|local_|param_)|^(if|while|for|switch|return|sizeof|true|false)$")


class FixtureDecompilerBackend:
    def __init__(self, decompiled: str):
        self.text = decompiled
        self.functions: dict[str, str] = {}
        for m in _FN_HDR.finditer(decompiled):
            name = m.group(2)
            start = m.start()
            depth = 0
            end = len(decompiled)
            for i in range(m.end() - 1, len(decompiled)):
                if decompiled[i] == "{":
                    depth += 1
                elif decompiled[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            self.functions[name] = decompiled[start:end]

    def list_functions(self) -> str:
        return "\n".join(f"{name}  ({len(body.splitlines())} lines)" for name, body in self.functions.items()) or "(none)"

    def decompile_function(self, name: str) -> str:
        name = name.strip()
        if name in self.functions:
            return self.functions[name]
        for k in self.functions:
            if k.lower() == name.lower() or k.endswith(name):
                return self.functions[k]
        return f"error: no function named {name!r}"

    def list_strings(self) -> str:
        seen: list[str] = []
        for m in _STR.finditer(self.text):
            s = m.group(1)
            if len(s) >= 4 and s not in seen:
                seen.append(s)
        return "\n".join(seen) or "(none)"

    def list_imports(self) -> str:
        names: list[str] = []
        for m in _CALL.finditer(self.text):
            n = m.group(1)
            if n in self.functions or _NOT_IMPORT.match(n) or n in names:
                continue
            names.append(n)
        return "\n".join(names) or "(none)"


# ---------------------------------------------------------------------------
# radare2
# ---------------------------------------------------------------------------


class R2Backend:
    """Drives radare2 on an ELF. Uses r2pipe when installed, else one-shot r2 calls."""

    def __init__(self, path: str, r2_bin: str | None = None):
        self.path = path
        self.r2 = r2_bin or shutil.which("r2") or shutil.which("radare2")
        if not self.r2:
            raise RuntimeError("radare2 not found in PATH")
        self._pipe = None
        try:
            import r2pipe  # type: ignore

            self._pipe = r2pipe.open(path, flags=["-2", "-e", "scr.color=0"])
            self._pipe.cmd("aaa")
        except Exception:
            self._pipe = None

    def _cmd(self, cmd: str) -> str:
        if self._pipe is not None:
            return self._pipe.cmd(cmd) or ""
        out = subprocess.run(
            [self.r2, "-q", "-2", "-e", "scr.color=0", "-c", f"aaa; {cmd}", self.path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return out.stdout

    def close(self):
        if self._pipe is not None:
            try:
                self._pipe.quit()
            except Exception:
                pass

    def list_functions(self) -> str:
        try:
            fns = json.loads(self._cmd("aflj") or "[]")
        except ValueError:
            return self._cmd("afl")
        rows = []
        for f in fns:
            name = f.get("name", "")
            if name.startswith(("sym.imp.", "fcn.", "entry.init", "entry.fini")) or name in (
                "sym._init",
                "sym._fini",
                "sym.deregister_tm_clones",
                "sym.register_tm_clones",
                "sym.__do_global_dtors_aux",
                "sym.frame_dummy",
                "entry0",
            ):
                continue
            rows.append(f"{name}  (size {f.get('size', '?')})")
        return "\n".join(rows) or "(none)"

    def decompile_function(self, name: str) -> str:
        name = name.strip()
        if not re.fullmatch(r"[\w.]+", name):
            return "error: invalid function name"
        candidates = [name, f"sym.{name}", "main" if name in ("sym.main", "_main") else name]
        for c in candidates:
            out = self._cmd(f"pdc @ {c}")
            if out.strip() and "Cannot find function" not in out and "Invalid address" not in out:
                return out
        return f"error: no function named {name!r}"

    def list_strings(self) -> str:
        try:
            data = json.loads(self._cmd("izj") or "[]")
            return "\n".join(s.get("string", "") for s in data) or "(none)"
        except ValueError:
            return self._cmd("iz")

    def list_imports(self) -> str:
        try:
            data = json.loads(self._cmd("iij") or "[]")
            return "\n".join(i.get("name", "") for i in data) or "(none)"
        except ValueError:
            return self._cmd("ii")


# ---------------------------------------------------------------------------
# GhidraMCP HTTP (experimental, untested here)
# ---------------------------------------------------------------------------


class GhidraMCPBackend:
    DEFAULT_ENDPOINTS = {
        "list_functions": ("GET", "methods"),
        "decompile_function": ("POST", "decompile"),
        "list_strings": ("GET", "strings"),
        "list_imports": ("GET", "imports"),
    }

    def __init__(self, base_url: str = "http://127.0.0.1:8080/", endpoints: dict | None = None, timeout: float = 60):
        self.base = base_url.rstrip("/") + "/"
        self.endpoints = {**self.DEFAULT_ENDPOINTS, **(endpoints or {})}
        self.timeout = timeout

    def _call(self, tool: str, payload: str | None = None, params: dict | None = None) -> str:
        method, path = self.endpoints[tool]
        url = urllib.parse.urljoin(self.base, path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = payload.encode() if (method == "POST" and payload is not None) else None
        req = urllib.request.Request(url, data=data, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def list_functions(self) -> str:
        return self._call("list_functions", params={"offset": 0, "limit": 200})

    def decompile_function(self, name: str) -> str:
        return self._call("decompile_function", payload=name)

    def list_strings(self) -> str:
        return self._call("list_strings", params={"offset": 0, "limit": 500})

    def list_imports(self) -> str:
        return self._call("list_imports", params={"offset": 0, "limit": 500})
