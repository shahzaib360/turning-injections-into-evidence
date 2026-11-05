"""OpenAI-compatible chat endpoint (Ollama, vLLM, llama.cpp server, hosted APIs)."""

from __future__ import annotations

import json
import os
import time
import urllib.request

from tie.llm.base import ChatResult


class OpenAICompatModel:
    def __init__(self, model: str, base_url: str, api_key: str | None = None, timeout: float = 600, **_):
        self.model = model
        self.name = model.replace("/", "_").replace(":", "_")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "not-needed")
        self.timeout = timeout

    def chat(self, messages, max_tokens=256, temperature=0.0, stop=None) -> ChatResult:
        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if stop:
            body["stop"] = stop
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        usage = data.get("usage") or {}
        return ChatResult(
            text=data["choices"][0]["message"].get("content") or "",
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            elapsed_s=time.time() - t0,
        )
