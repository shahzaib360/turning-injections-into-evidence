"""Local GGUF models through llama-cpp-python (CPU friendly)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from tie.llm.base import ChatResult, merge_system


class LlamaCppModel:
    def __init__(self, path: str, n_ctx: int = 6144, n_threads: int | None = None, seed: int = 0, **_):
        from llama_cpp import Llama  # imported lazily: optional dependency

        self.path = path
        self.name = Path(path).stem
        self._llm = Llama(
            model_path=path,
            n_ctx=n_ctx,
            n_threads=n_threads or os.cpu_count() or 4,
            seed=seed,
            verbose=False,
        )
        tmpl = (self._llm.metadata or {}).get("tokenizer.chat_template", "") or ""
        self._needs_merge = "gemma" in self.name.lower() or "System role not supported" in tmpl
        self.n_ctx = n_ctx

    def count_tokens(self, text: str) -> int:
        return len(self._llm.tokenize(text.encode("utf-8"), add_bos=False))

    def chat(self, messages, max_tokens=256, temperature=0.0, stop=None) -> ChatResult:
        if self._needs_merge:
            messages = merge_system(messages)
        t0 = time.time()
        out = self._llm.create_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=1.0,
            stop=stop,
            seed=0,
        )
        usage = out.get("usage", {})
        return ChatResult(
            text=out["choices"][0]["message"]["content"] or "",
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            elapsed_s=time.time() - t0,
        )
