"""Standard-LLM provider for Aegis — local-first, OpenAI-compatible.

Aegis has two model seams:

1. The **typed decision layer** (:mod:`aegis.decision`) — ``choose`` / ``score``
   / ``boolean`` with a probability. This is the gate/triage/validate oracle.
2. A **standard generative LLM** — the "writes & plans" model, exactly what
   Strix drives through LiteLLM. That is this module.

A standard LLM can serve *both* roles: :func:`judge_backend` wraps any
:class:`LLMProvider` into the existing :class:`LLMJudgeBackend`, so a plain chat
model can drive the decisions too (selected with ``backend="llm"``).

Everything is **local-first**: :class:`OpenAICompatProvider` defaults to a
localhost endpoint (the OpenAI-compatible API that Ollama / llama.cpp / vLLM /
LM Studio all speak), and talking to a non-localhost host is refused unless
``local_only`` is explicitly disabled — the same egress policy as the Jev
backend. With nothing configured, :class:`TemplateLLM` answers deterministically
and offline, so a run never requires a server.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import List, Optional, Protocol, Sequence, runtime_checkable
from urllib.parse import urlparse

from aegis.decision.client import LLMJudgeBackend

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


class LLMError(RuntimeError):
    """Raised when a generative LLM call cannot be completed."""


@runtime_checkable
class LLMProvider(Protocol):
    """A standard text-generation model. ``complete`` is the minimal surface."""

    name: str

    def complete(self, prompt: str) -> str: ...

    def chat(self, messages: Sequence[dict]) -> str: ...


def is_local_base(api_base: str) -> bool:
    """True if ``api_base`` points at the local machine."""
    host = (urlparse(api_base).hostname or "").lower()
    return host in _LOCAL_HOSTS


class TemplateLLM:
    """Deterministic, offline stand-in generative model.

    Produces stable, parseable output with no network — so the ``llm`` decision
    backend and the engines' generative steps run end-to-end in tests. Decision
    prompts (asking for a JSON object) get a deterministic JSON reply whose
    values derive from a stable hash of the prompt; free-form prompts get a
    short templated summary. It is NOT a ground-truth oracle (use the ``static``
    backend for that) — it exercises the standard-model code path deterministically.
    """

    def __init__(self, name: str = "template-llm") -> None:
        self.name = name

    @staticmethod
    def _unit(text: str) -> float:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return (int(digest[:8], 16) % 1000) / 1000.0

    def complete(self, prompt: str) -> str:
        low = prompt.lower()
        if "reply only as json" in low or '{"' in prompt or "json:" in low:
            u = self._unit(prompt)
            if '"index"' in prompt:
                return json.dumps({"index": 0, "probability": round(u, 3)})
            if '"value"' in prompt:
                # Mid-scale-ish deterministic value in a 0..10 frame.
                return json.dumps({"value": round(1.0 + u * 8.0, 3)})
            return json.dumps({"probability": round(u, 3)})
        head = " ".join(prompt.split()[:24])
        return f"[template-llm summary] {head}"

    def chat(self, messages: Sequence[dict]) -> str:
        joined = "\n".join(m.get("content", "") for m in messages)
        return self.complete(joined)


class OpenAICompatProvider:
    """Standard LLM over the OpenAI-compatible Chat Completions API (stdlib only).

    Config (env-first; mirrors Strix's ``STRIX_LLM`` / ``LLM_API_BASE`` /
    ``LLM_API_KEY``):

    * ``AEGIS_LLM``          — model id (e.g. ``llama3.1`` / ``qwen2.5-coder``)
    * ``AEGIS_LLM_API_BASE`` — endpoint base (default ``http://localhost:11434/v1``)
    * ``AEGIS_LLM_API_KEY``  — optional bearer (local servers often need none)

    Local-first: a non-localhost ``api_base`` raises unless ``local_only=False``.
    """

    DEFAULT_BASE = "http://localhost:11434/v1"

    def __init__(
        self,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_s: float = 30.0,
        local_only: bool = True,
        temperature: float = 0.0,
    ) -> None:
        self.model = model or os.environ.get("AEGIS_LLM", "llama3.1")
        self.api_base = (api_base or os.environ.get("AEGIS_LLM_API_BASE")
                         or self.DEFAULT_BASE).rstrip("/")
        self.api_key = api_key or os.environ.get("AEGIS_LLM_API_KEY")
        self.timeout_s = timeout_s
        self.temperature = temperature
        self.name = f"llm:{self.model}"
        if local_only and not is_local_base(self.api_base):
            raise LLMError(
                f"LLM api_base {self.api_base!r} is not localhost; Aegis is "
                "local_only. Point AEGIS_LLM_API_BASE at a local server or set "
                "local_only=False / AEGIS_LOCAL_ONLY=0 to allow egress."
            )

    def chat(self, messages: Sequence[dict]) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps({
            "model": self.model,
            "messages": list(messages),
            "temperature": self.temperature,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.api_base + "/chat/completions", data=body, method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError,
                IndexError) as exc:
            raise LLMError(f"llm request failed: {exc}") from exc

    def complete(self, prompt: str) -> str:
        return self.chat([{"role": "user", "content": prompt}])


def build_llm(
    model: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
    local_only: bool = True,
) -> LLMProvider:
    """Return a configured provider, or the offline :class:`TemplateLLM`.

    A real :class:`OpenAICompatProvider` is built when a model or api_base is
    configured (via args or the ``AEGIS_LLM*`` env vars); otherwise the
    deterministic offline template provider is returned so Aegis always runs.
    """
    configured = any([
        model, api_base, api_key,
        os.environ.get("AEGIS_LLM"), os.environ.get("AEGIS_LLM_API_BASE"),
        os.environ.get("AEGIS_LLM_API_KEY"),
    ])
    if not configured:
        return TemplateLLM()
    return OpenAICompatProvider(
        model=model, api_base=api_base, api_key=api_key, local_only=local_only
    )


def judge_backend(provider: LLMProvider, name: str = "llm-judge") -> LLMJudgeBackend:
    """Adapt a standard :class:`LLMProvider` into a decision backend.

    This is how a plain chat model drives the typed decisions (triage, dedup,
    validate, score) — the standard-model decision path, equivalent to pointing
    Strix at an LLM. The returned backend degrades to ``DecisionError`` on model
    failure, so a fallback (e.g. the offline ``HintBackend``) can answer.
    """
    return LLMJudgeBackend(complete=provider.complete, name=name)


def summarize(provider: LLMProvider, title: str, context: str) -> str:
    """Generative helper: a short natural-language summary for a finding.

    The 'LLM writes' half of "LLM writes & plans, the decision model decides".
    Falls back to a deterministic template if the provider fails, so a run never
    breaks on a flaky model.
    """
    prompt = (
        "Summarize this security finding in one neutral sentence for a report. "
        f"Title: {title}\nContext: {context}"
    )
    try:
        return provider.complete(prompt).strip()
    except LLMError:
        return f"{title} — {context[:140]}"


def plan_next_action(
    provider: LLMProvider, state: str, options: Sequence[str]
) -> tuple[int, str]:
    """The 'LLM plans' half: pick the next action and say why, in the LLM's words.

    Returns ``(index, rationale)`` into ``options``. Any failure (network, bad
    JSON, out-of-range) falls back to ``(0, "")`` — option 0 is always the
    sensible next action — so the loop stays safe and deterministic offline.
    """
    opts = list(options)
    if not opts:
        return 0, ""
    numbered = "\n".join(f"{i}: {o}" for i, o in enumerate(opts))
    prompt = (
        "You are the coordinator agent driving a defensive security test of an "
        "authorized target. Choose the single next action and explain why.\n\n"
        f"Current state: {state}\n\nActions:\n{numbered}\n\n"
        'Reply ONLY as JSON: {"action_index": <int>, '
        '"rationale": "<one short sentence>"}'
    )
    try:
        text = provider.complete(prompt)
        lo, hi = text.find("{"), text.rfind("}")
        if lo == -1 or hi == -1:
            return 0, ""
        data = json.loads(text[lo:hi + 1])
        idx = max(0, min(int(data.get("action_index", 0)), len(opts) - 1))
        return idx, str(data.get("rationale", "")).strip()[:200]
    except (LLMError, ValueError, KeyError, TypeError):
        return 0, ""


def agent_turn(
    provider: LLMProvider, role: str, task: str, state: str,
    options: Sequence[str]
) -> dict:
    """One generative agent turn: assistant prose + a think note + an action.

    Returns ``{"assistant", "think", "action_index", "rationale"}``. This is the
    transcript content Strix-style agents emit each turn. Any failure falls back
    to a terse deterministic turn choosing option 0, so a run never breaks.
    """
    opts = list(options)
    fallback = {
        "assistant": f"Continuing the {role} task: {task}.",
        "think": "", "action_index": 0,
        "rationale": "proceed with the next action",
    }
    if not opts:
        return fallback
    numbered = "\n".join(f"{i}: {o}" for i, o in enumerate(opts))
    prompt = (
        f"You are the {role} agent in a defensive security test of an authorized "
        f"target. Your task: {task}.\nCurrent state: {state}\n\n"
        f"Available next actions:\n{numbered}\n\n"
        "Respond ONLY as JSON with your reasoning and the chosen action:\n"
        '{"assistant": "<1-2 sentences on what you observe and intend>", '
        '"think": "<a brief private reasoning note>", '
        '"action_index": <int>, "rationale": "<one sentence: why this action>"}'
    )
    try:
        text = provider.complete(prompt)
        lo, hi = text.find("{"), text.rfind("}")
        if lo == -1 or hi == -1:
            return fallback
        data = json.loads(text[lo:hi + 1])
        idx = max(0, min(int(data.get("action_index", 0)), len(opts) - 1))
        return {
            "assistant": str(data.get("assistant", "")).strip()[:600] or fallback["assistant"],
            "think": str(data.get("think", "")).strip()[:600],
            "action_index": idx,
            "rationale": str(data.get("rationale", "")).strip()[:200],
        }
    except (LLMError, ValueError, KeyError, TypeError):
        return fallback


def explain_finding(provider: LLMProvider, title: str, evidence: Sequence[str]) -> str:
    """The 'LLM writes' half for a confirmed finding: one authored sentence."""
    ev = "; ".join(evidence) if evidence else "no recorded evidence"
    try:
        return provider.complete(
            "In one sentence, explain to a security reviewer why this finding is "
            f"a real, exploitable issue. Title: {title}. Evidence: {ev}."
        ).strip()[:280]
    except LLMError:
        return ""


__all__ = [
    "LLMProvider", "LLMError", "TemplateLLM", "OpenAICompatProvider",
    "build_llm", "judge_backend", "summarize", "plan_next_action",
    "agent_turn", "explain_finding", "is_local_base",
]
