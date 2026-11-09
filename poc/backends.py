"""Decision backends and router construction for the POC.

The pipeline makes every decision through a ``DecisionRouter`` (from
``reference.jev``). To keep the demo deterministic and offline, the default
backend is a ``HintBackend`` stand-in that resolves each decision from the
sample data's ground-truth ``hints`` via a machine-readable ``[ref=...]`` tag
embedded at the end of each decision statement.

Real backends (basal-omni / Jev) read the natural-language statement and ignore
the tag; selecting them keeps ``HintBackend`` as a fallback so the demo still
completes without a model server.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Sequence

from reference.jev import (
    BasalOmniBackend,
    BooleanResult,
    ChoiceResult,
    DecisionClient,
    DecisionRouter,
    JevBackend,
    ScoreResult,
)
from reference.jev.decision_client import StaticBackend

from .models import Candidate

# Per-decision thresholds. Triage is low (keep unless clearly a false positive);
# dedup is higher (only collapse on a confident match).
POC_THRESHOLDS = {
    "triage.true_positive": 0.4,
    "dedupe.same_vuln": 0.6,
    # exploitability stages share one threshold here for simplicity
    "validate.stage": 0.5,
}
POSTERIOR_MIN = 0.5

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
    backend: str = "static",
    log_path: Optional[str | Path] = None,
) -> DecisionRouter:
    """Build a DecisionRouter for the POC.

    ``backend``:
      * ``static`` (default) — HintBackend only, fully offline/deterministic.
      * ``basal``            — BasalOmniBackend primary, HintBackend fallback.
      * ``jev``              — JevBackend primary, HintBackend fallback.
    """
    hint = HintBackend(candidates)
    if backend == "static":
        client = DecisionClient(primary=hint)
    elif backend == "basal":
        client = DecisionClient(primary=BasalOmniBackend(), fallback=hint)
    elif backend == "jev":
        client = DecisionClient(primary=JevBackend(), fallback=hint)
    else:
        raise ValueError(f"unknown backend {backend!r} (static|basal|jev)")
    return DecisionRouter(
        client,
        thresholds=POC_THRESHOLDS,
        log_path=log_path,
        default_threshold=0.5,
    )


__all__ = ["HintBackend", "build_router", "POC_THRESHOLDS", "POSTERIOR_MIN",
           "StaticBackend"]
