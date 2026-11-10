"""Provider-agnostic decision client for security-agent frameworks.

This module is the *only* place that knows about a concrete decision provider
(TypeSafe's Jev API). Everything else in the codebase depends on the
``DecisionBackend`` protocol, so swapping Jev for an LLM-as-judge, a local
model, or a static rule set is a one-line change at wiring time.

Design goals
------------
* **No hard dependency on any vendor.** ``JevBackend`` is one backend among
  several. The library runs fully offline with ``StaticBackend``.
* **Typed decisions.** Three primitives only — ``choose`` / ``score`` /
  ``boolean`` — each returning a result with an explicit probability, so
  callers never parse free-form model prose.
* **Graceful degradation.** ``DecisionClient`` wraps a primary backend and an
  optional fallback; if the primary is unconfigured, times out, or errors, the
  fallback answers instead of crashing the agent loop.

Only the Python standard library is used, so this file is importable and
testable without installing anything or reaching the network.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence, runtime_checkable


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ChoiceResult:
    """Result of a choose-one decision."""

    index: int
    option: str
    probability: float
    backend: str
    latency_ms: float = 0.0
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreResult:
    """Result of a score-on-a-scale decision."""

    value: float
    scale_min: float
    scale_max: float
    backend: str
    latency_ms: float = 0.0
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class BooleanResult:
    """Result of a yes/no decision.

    ``probability`` is P(statement is true). ``decide(threshold)`` turns it into
    a hard boolean, which is what makes gated agent logic unit-testable.
    """

    probability: float
    backend: str
    latency_ms: float = 0.0
    raw: dict = field(default_factory=dict)

    def decide(self, threshold: float = 0.5) -> bool:
        return self.probability >= threshold


# --------------------------------------------------------------------------- #
# Backend protocol
# --------------------------------------------------------------------------- #
@runtime_checkable
class DecisionBackend(Protocol):
    """A source of typed decisions. Implement these three methods."""

    name: str

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult: ...

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult: ...

    def boolean(self, statement: str) -> BooleanResult: ...


class DecisionError(RuntimeError):
    """Raised by a backend when it cannot produce a decision."""


# --------------------------------------------------------------------------- #
# JevBackend — the one place that knows TypeSafe's wire format
# --------------------------------------------------------------------------- #
# TypeSafe's Jev decision API (and a LiteLLM gateway proxying it) exposes ONE
# typed-decision endpoint, ``POST {base}/decisions``:
#
#   request : {"model", "input": <text judged>, "questions": [ <question> ]}
#   question: {"type": "predicate"|"choice"|"score", "instructions", ...}
#             choice adds "choices": [{"value": <str|bool>, "description"?}]
#             score  adds "levels":  [<label>, ...]  (lowest → highest)
#   response: {"answers": [ <answer> ], ...}   (answers echo question order)
#             predicate → {"probability"}
#             choice    → {"choice", "probabilities", "confidence"}
#             score     → {"score": <level index>, "probabilities", "confidence"}
#             refusal   → {"type": "refusal"}   (model declined)
#
# Verified against a live gateway's OpenAPI schema. Jev is a *typed-decision*
# model, not a chat model, so it is NOT reachable via /chat/completions.
_JEV_DEFAULT_BASE = "https://api.typesafe.ai/v1"
_JEV_DECISIONS_PATH = "/decisions"

# How many discrete levels a continuous score() is quantised into for Jev.
# The API caps `levels` at 10 (minItems 2, maxItems 10).
_JEV_SCORE_LEVELS = 10

# Response field names shared by the BasalOmni self-hosted backend below.
_RESP_CHOICE_INDEX = "choice_index"
_RESP_PROBABILITY = "probability"
_RESP_SCORE_VALUE = "value"


class JevBackend:
    """Calls TypeSafe's Jev decision API over HTTPS using only stdlib.

    Configuration is environment-first so it slots into Strix
    (``~/.strix/cli-config.json`` style env) and RAPTOR (dispatcher env) without
    new plumbing:

    * ``JEV_API_BASE``  — endpoint base (default ``https://api.typesafe.ai/v1``)
    * ``JEV_API_KEY``   — bearer credential (required to actually call)
    * ``JEV_MODEL``     — model id, e.g. ``jev-1.13.0``
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        timeout_s: float = 5.0,
    ) -> None:
        self.name = "jev"
        self.api_key = api_key or os.environ.get("JEV_API_KEY")
        self.api_base = (api_base or os.environ.get("JEV_API_BASE")
                         or _JEV_DEFAULT_BASE).rstrip("/")
        self.model = model or os.environ.get("JEV_MODEL", "jev-1.13.0")
        self.timeout_s = timeout_s

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _decide(self, input_text: str, question: dict) -> tuple[dict, float, dict]:
        """POST one typed-decision question; return (answer, ms, full_response).

        Raises ``DecisionError`` when the key is missing, the request fails, or
        the model refuses — so the caller's fallback backend takes over.
        """
        if not self.configured:
            raise DecisionError("JEV_API_KEY is not set")
        body = json.dumps({
            "model": self.model, "input": input_text, "questions": [question],
        }).encode("utf-8")
        req = urllib.request.Request(
            self.api_base + _JEV_DECISIONS_PATH, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise DecisionError(f"jev request failed: {exc}") from exc
        ms = (time.perf_counter() - start) * 1000.0
        answers = data.get("answers") or []
        if not answers:
            raise DecisionError("jev decisions returned no answers")
        answer = answers[0]
        if answer.get("type") == "refusal":
            raise DecisionError("jev model refused the decision")
        return answer, ms, data

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult:
        opts = list(options)
        if not opts:
            raise DecisionError("choose() requires at least one option")
        answer, ms, data = self._decide(prompt, {
            "type": "choice",
            "instructions": "Select the single best option for the situation.",
            "choices": [{"value": o} for o in opts],
        })
        chosen = answer.get("choice")
        idx = opts.index(chosen) if chosen in opts else 0
        return ChoiceResult(
            index=idx,
            option=opts[idx],
            probability=float(answer.get("confidence", 0.0)),
            backend=self.name,
            latency_ms=ms,
            raw=data,
        )

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult:
        # Jev scores against discrete levels and returns the level index; build
        # a linear ladder across the range and map the index back to a value.
        n = _JEV_SCORE_LEVELS
        span = scale_max - scale_min
        levels = [{"label": str(round(scale_min + i * span / (n - 1), 4))}
                  for i in range(n)]
        answer, ms, data = self._decide(prompt, {
            "type": "score",
            "instructions": "Score the item described on the given scale.",
            "levels": levels,
        })
        # Jev returns a fractional level index (probability-weighted); keep the
        # fraction and interpolate across the range rather than truncating.
        lvl = max(0.0, min(float(answer.get("score", 0)), float(n - 1)))
        value = scale_min + lvl * span / (n - 1)
        return ScoreResult(
            value=value,
            scale_min=scale_min,
            scale_max=scale_max,
            backend=self.name,
            latency_ms=ms,
            raw=data,
        )

    def boolean(self, statement: str) -> BooleanResult:
        answer, ms, data = self._decide(statement, {
            "type": "predicate",
            "instructions": "Is this statement true?",
        })
        return BooleanResult(
            probability=float(answer.get("probability", 0.0)),
            backend=self.name,
            latency_ms=ms,
            raw=data,
        )


# --------------------------------------------------------------------------- #
# BasalOmniBackend — open-weight, self-hosted, multimodal (Gemma 4)
# --------------------------------------------------------------------------- #
# basal-omni (Remigiusz Kinas / "Remek", open weights on Hugging Face) is a
# System One decision model served behind a `/v1/systemone` endpoint with
# `choice` / `score` modes. Because it is self-hostable it keeps target code and
# responses *inside your own infrastructure* — the right default when the thing
# being analyzed is sensitive/proprietary (i.e. most security work). The `omni`
# variants also accept images, so Strix browser screenshots or rendered
# artifacts can be passed through `image_refs` without flattening to text first.
#
# Endpoint/field names are isolated here (verify against the model card); the
# default base points at a local inference server.
_BASAL_DEFAULT_BASE = "http://localhost:8000/v1"
_BASAL_SYSTEMONE_PATH = "/systemone"
_BASAL_MODE_CHOICE = "choice"
_BASAL_MODE_SCORE = "score"


class BasalOmniBackend:
    """Self-hosted basal-omni backend (Jev-compatible, multimodal, no egress).

    Config (env-first, mirrors the Jev/Strix/RAPTOR pattern):

    * ``BASAL_API_BASE`` — endpoint base (default ``http://localhost:8000/v1``)
    * ``BASAL_API_KEY``  — optional bearer (local servers often need none)
    * ``BASAL_MODEL``    — e.g. ``basal-omni-1.0-ultra``

    ``boolean`` is implemented via the model's ``score`` mode over a 0..1 scale,
    i.e. a direct probability estimate — same semantics as Jev's boolean.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        timeout_s: float = 5.0,
    ) -> None:
        self.name = "basal-omni"
        self.api_key = api_key or os.environ.get("BASAL_API_KEY")
        self.api_base = (api_base or os.environ.get("BASAL_API_BASE")
                         or _BASAL_DEFAULT_BASE).rstrip("/")
        self.model = model or os.environ.get("BASAL_MODEL", "basal-omni-1.0-ultra")
        self.timeout_s = timeout_s

    def _post(self, payload: dict) -> tuple[dict, float]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps({"model": self.model, **payload}).encode("utf-8")
        req = urllib.request.Request(
            self.api_base + _BASAL_SYSTEMONE_PATH,
            data=body,
            method="POST",
            headers=headers,
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise DecisionError(f"basal-omni request failed: {exc}") from exc
        return data, (time.perf_counter() - start) * 1000.0

    def choose(
        self,
        prompt: str,
        options: Sequence[str],
        image_refs: Optional[Sequence[str]] = None,
    ) -> ChoiceResult:
        opts = list(options)
        if not opts:
            raise DecisionError("choose() requires at least one option")
        payload = {"mode": _BASAL_MODE_CHOICE, "state": prompt, "options": opts}
        if image_refs:
            payload["images"] = list(image_refs)  # multimodal: zero-shot images
        data, ms = self._post(payload)
        idx = int(data.get(_RESP_CHOICE_INDEX, 0))
        idx = max(0, min(idx, len(opts) - 1))
        return ChoiceResult(idx, opts[idx],
                            float(data.get(_RESP_PROBABILITY, 0.0)),
                            self.name, ms, data)

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult:
        data, ms = self._post(
            {"mode": _BASAL_MODE_SCORE, "state": prompt,
             "scale_min": scale_min, "scale_max": scale_max}
        )
        value = float(data.get(_RESP_SCORE_VALUE, scale_min))
        value = max(scale_min, min(value, scale_max))
        return ScoreResult(value, scale_min, scale_max, self.name, ms, data)

    def boolean(self, statement: str) -> BooleanResult:
        # Probability estimate via score mode on a 0..1 scale.
        data, ms = self._post(
            {"mode": _BASAL_MODE_SCORE, "state": statement,
             "scale_min": 0.0, "scale_max": 1.0}
        )
        prob = float(data.get(_RESP_SCORE_VALUE, data.get(_RESP_PROBABILITY, 0.0)))
        return BooleanResult(max(0.0, min(prob, 1.0)), self.name, ms, data)


# --------------------------------------------------------------------------- #
# LLMJudgeBackend — reuse whatever LLM the framework already has
# --------------------------------------------------------------------------- #
class LLMJudgeBackend:
    """Fallback that turns *any* text-completion callable into a decision maker.

    Pass a callable ``complete(prompt: str) -> str``. In Strix that wraps
    LiteLLM; in RAPTOR it wraps a call back through the dispatcher. The callable
    must return a short JSON object; this class owns the (strict) parsing so the
    rest of the system still sees typed results.
    """

    def __init__(self, complete: Callable[[str], str], name: str = "llm-judge"):
        self.name = name
        self._complete = complete

    def _ask_json(self, prompt: str) -> tuple[dict, float]:
        start = time.perf_counter()
        text = self._complete(prompt)
        ms = (time.perf_counter() - start) * 1000.0
        try:
            # Be tolerant of models that wrap JSON in prose/code fences.
            lo, hi = text.find("{"), text.rfind("}")
            if lo == -1 or hi == -1:
                raise ValueError("no JSON object in completion")
            return json.loads(text[lo : hi + 1]), ms
        except ValueError as exc:
            raise DecisionError(f"llm-judge returned non-JSON: {exc}") from exc

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult:
        opts = list(options)
        numbered = "\n".join(f"{i}: {o}" for i, o in enumerate(opts))
        data, ms = self._ask_json(
            f"{prompt}\n\nOptions:\n{numbered}\n\n"
            'Reply ONLY as JSON: {"index": <int>, "probability": <0..1>}'
        )
        idx = max(0, min(int(data.get("index", 0)), len(opts) - 1))
        return ChoiceResult(idx, opts[idx], float(data.get("probability", 0.0)),
                            self.name, ms, data)

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult:
        data, ms = self._ask_json(
            f"{prompt}\n\nScore on a scale from {scale_min} to {scale_max}. "
            'Reply ONLY as JSON: {"value": <number>}'
        )
        value = max(scale_min, min(float(data.get("value", scale_min)), scale_max))
        return ScoreResult(value, scale_min, scale_max, self.name, ms, data)

    def boolean(self, statement: str) -> BooleanResult:
        data, ms = self._ask_json(
            f"Statement: {statement}\n\n"
            'Estimate the probability it is true. '
            'Reply ONLY as JSON: {"probability": <0..1>}'
        )
        return BooleanResult(float(data.get("probability", 0.0)), self.name, ms,
                             data)


# --------------------------------------------------------------------------- #
# StaticBackend — deterministic, offline (tests and --no-llm mode)
# --------------------------------------------------------------------------- #
class StaticBackend:
    """Deterministic backend for tests and RAPTOR's ``--no-llm`` mode.

    Takes plain rule callables so a run is fully reproducible with no network
    and no model. Defaults are intentionally conservative (boolean defaults to
    0.5 so a 0.5 threshold *keeps* the finding).
    """

    def __init__(
        self,
        choose_fn: Optional[Callable[[str, Sequence[str]], int]] = None,
        score_fn: Optional[Callable[[str, float, float], float]] = None,
        boolean_fn: Optional[Callable[[str], float]] = None,
        name: str = "static",
    ) -> None:
        self.name = name
        self._choose = choose_fn or (lambda prompt, opts: 0)
        self._score = score_fn or (lambda prompt, lo, hi: (lo + hi) / 2.0)
        self._boolean = boolean_fn or (lambda statement: 0.5)

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult:
        opts = list(options)
        idx = max(0, min(int(self._choose(prompt, opts)), len(opts) - 1))
        return ChoiceResult(idx, opts[idx], 1.0, self.name, 0.0, {})

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult:
        value = max(scale_min, min(self._score(prompt, scale_min, scale_max),
                                   scale_max))
        return ScoreResult(value, scale_min, scale_max, self.name, 0.0, {})

    def boolean(self, statement: str) -> BooleanResult:
        return BooleanResult(float(self._boolean(statement)), self.name, 0.0, {})


# --------------------------------------------------------------------------- #
# DecisionClient — primary + fallback with graceful degradation
# --------------------------------------------------------------------------- #
class DecisionClient:
    """Wraps a primary backend and an optional fallback.

    If the primary raises :class:`DecisionError` (unconfigured, timeout, bad
    response), the fallback answers. This guarantees an agent loop never hard
    fails because a decision provider is unavailable.
    """

    def __init__(
        self,
        primary: DecisionBackend,
        fallback: Optional[DecisionBackend] = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback

    def _run(self, method: str, *args):
        try:
            return getattr(self.primary, method)(*args)
        except DecisionError:
            if self.fallback is None:
                raise
            return getattr(self.fallback, method)(*args)

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult:
        return self._run("choose", prompt, options)

    def score(
        self, prompt: str, scale_min: float, scale_max: float
    ) -> ScoreResult:
        return self._run("score", prompt, scale_min, scale_max)

    def boolean(self, statement: str) -> BooleanResult:
        return self._run("boolean", statement)

    @classmethod
    def from_env(
        cls, fallback: Optional[DecisionBackend] = None
    ) -> "DecisionClient":
        """Build a Jev-primary client from env, with an optional fallback.

        If ``JEV_API_KEY`` is unset the Jev backend simply degrades to the
        fallback on first use, so this is safe to call unconditionally.
        """
        return cls(primary=JevBackend(), fallback=fallback)
