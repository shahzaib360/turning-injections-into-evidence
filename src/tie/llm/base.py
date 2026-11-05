"""Minimal chat-model interface used by every pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ChatResult:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    elapsed_s: float = 0.0


class ChatModel(Protocol):
    name: str

    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 256,
        temperature: float = 0.0,
        stop: list[str] | None = None,
    ) -> ChatResult: ...


def merge_system(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Fold a leading system message into the first user turn.

    Some chat templates (e.g. Gemma 2) reject the ``system`` role.
    """
    if not messages or messages[0]["role"] != "system":
        return messages
    sys_msg, rest = messages[0], list(messages[1:])
    if rest and rest[0]["role"] == "user":
        rest[0] = {"role": "user", "content": sys_msg["content"] + "\n\n" + rest[0]["content"]}
    else:
        rest.insert(0, {"role": "user", "content": sys_msg["content"]})
    # Gemma also requires strict user/assistant alternation.
    fixed: list[dict[str, str]] = []
    for m in rest:
        if fixed and fixed[-1]["role"] == m["role"]:
            fixed[-1] = {"role": m["role"], "content": fixed[-1]["content"] + "\n\n" + m["content"]}
        else:
            fixed.append(dict(m))
    return fixed


def load_model(spec: str, **kw) -> ChatModel:
    """Create a model from a spec string.

    * ``llamacpp:/path/to/model.gguf``   - local GGUF via llama-cpp-python
    * ``openai:<model>@<base_url>``      - any OpenAI-compatible server
                                           (Ollama, vLLM, llama.cpp server, ...)
    * ``scripted:naive`` / ``scripted:robust`` - deterministic mocks for tests
    """
    kind, _, rest = spec.partition(":")
    if kind == "llamacpp":
        from tie.llm.llamacpp import LlamaCppModel

        return LlamaCppModel(rest, **kw)
    if kind == "openai":
        from tie.llm.openai_compat import OpenAICompatModel

        model, _, base = rest.partition("@")
        return OpenAICompatModel(model, base or "http://localhost:11434/v1", **kw)
    if kind == "scripted":
        from tie.llm.scripted import ScriptedAnalyst

        return ScriptedAnalyst(mode=rest or "naive")
    raise ValueError(f"unknown model spec {spec!r}")
