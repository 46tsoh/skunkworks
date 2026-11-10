"""Decision backends and router construction for the analysis pipeline.

Every pipeline decision goes through a :class:`DecisionRouter`. To stay
deterministic and fully offline, the default backend is a :class:`HintBackend`
stand-in that resolves each decision from sample ground-truth ``hints`` via a
machine-readable ``[ref=...]`` tag the pipeline appends to each statement.

Real backends (``basal`` localhost / ``jev`` remote) read the natural-language
statement and ignore the tag; selecting them keeps ``HintBackend`` as the
fallback so a run still completes without a model server. Selecting ``jev``
requires explicitly disabling ``local_only`` (see :mod:`aegis.config`).
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Optional, Sequence, Union

from aegis.config import AegisConfig
from aegis.decision import (
    BasalOmniBackend,
    BooleanResult,
    ChoiceResult,
    DecisionClient,
    DecisionRouter,
    JevBackend,
    ScoreResult,
)
from aegis.knowledge.models import Candidate

_REF_RE = re.compile(r"\[ref=([^\]]+)\]")


class HintBackend:
    """Deterministic offline stand-in driven by sample-data ground truth.

    Statements carry a trailing ``[ref=KEY]`` the pipeline adds:

    * ``[ref=<id>]`` on a ``boolean`` call  -> triage true-positive probability
    * ``[ref=<id>]`` on a ``score`` call    -> hypothesis evidence strength
    * ``[ref=<cand>|<exist>]``              -> dedup (same underlying vuln?)
    * ``[ref=<id>#<stage_index>]``          -> exploitability gate for a stage
    """

    def __init__(self, candidates: Sequence[Candidate], name: str = "hint") -> None:
        self.name = name
        self._by_id = {c.id: c for c in candidates}

    @staticmethod
    def _ref(text: str) -> Optional[str]:
        m = _REF_RE.search(text)
        return m.group(1) if m else None

    def boolean(self, statement: str) -> BooleanResult:
        ref = self._ref(statement)
        if ref is None:
            return BooleanResult(0.8, self.name)
        if "|" in ref:  # dedup: cand|exist
            cand_id, _, exist_id = ref.partition("|")
            cand = self._by_id.get(cand_id)
            dup = bool(cand and cand.hints.get("duplicate_of") == exist_id)
            return BooleanResult(0.96 if dup else 0.03, self.name)
        if "#" in ref:  # exploitability stage
            cand_id, _, idx = ref.partition("#")
            cand = self._by_id.get(cand_id)
            passes = int((cand.hints if cand else {}).get("exploit_stages_pass", 8))
            return BooleanResult(0.95 if int(idx) < passes else 0.05, self.name)
        # triage true-positive
        cand = self._by_id.get(ref)
        prob = float((cand.hints if cand else {}).get("true_positive_prob", 0.8))
        return BooleanResult(prob, self.name)

    def score(self, prompt: str, scale_min: float, scale_max: float) -> ScoreResult:
        ref = self._ref(prompt)
        cand = self._by_id.get(ref) if ref else None
        strength = float((cand.hints if cand else {}).get("evidence_strength", 0.5))
        value = scale_min + strength * (scale_max - scale_min)
        return ScoreResult(value, scale_min, scale_max, self.name)

    def choose(self, prompt: str, options: Sequence[str]) -> ChoiceResult:
        opts = list(options)
        return ChoiceResult(0, opts[0] if opts else "", 1.0, self.name)


def build_router(
    candidates: Sequence[Candidate],
    backend: Optional[str] = None,
    config: Optional[AegisConfig] = None,
    log_path: Optional[Union[str, Path]] = None,
) -> DecisionRouter:
    """Build a :class:`DecisionRouter` for the analysis pipeline.

    ``config`` fully specifies thresholds/backend/log; ``backend`` and
    ``log_path`` are convenience overrides (and keep the original POC call
    signature working). With no arguments the default offline ``static``
    configuration is used.
    """
    if config is None:
        kwargs: dict = {}
        if backend is not None:
            kwargs["backend"] = backend
        if log_path is not None:
            kwargs["log_path"] = log_path
        config = AegisConfig(**kwargs)
    elif log_path is not None:
        config = replace(config, log_path=Path(log_path))

    hint = HintBackend(candidates)
    if config.backend == "static":
        client = DecisionClient(primary=hint)
    elif config.backend == "basal":
        client = DecisionClient(primary=BasalOmniBackend(), fallback=hint)
    elif config.backend == "jev":
        client = DecisionClient(primary=JevBackend(), fallback=hint)
    elif config.backend == "llm":
        # A standard generative LLM driving the typed decisions (Strix-style),
        # local-first, with the offline HintBackend as the fallback.
        from aegis.llm import build_llm, judge_backend
        provider = build_llm(
            model=config.llm_model, api_base=config.llm_api_base,
            api_key=config.llm_api_key, local_only=config.local_only,
        )
        client = DecisionClient(primary=judge_backend(provider), fallback=hint)
    else:  # pragma: no cover - AegisConfig validates this
        raise ValueError(f"unknown backend {config.backend!r}")

    return DecisionRouter(
        client,
        thresholds=config.thresholds,
        log_path=config.log_path,
        default_threshold=config.default_threshold,
    )


__all__ = ["HintBackend", "build_router"]
