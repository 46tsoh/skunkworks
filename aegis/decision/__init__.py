"""Aegis decision layer: provider-agnostic typed decisions.

Promoted from the ``reference/jev`` research layer into the real ``aegis``
package. Three typed primitives (``choose`` / ``score`` / ``boolean``) flow
through a single observable :class:`DecisionRouter`, so every branch an engine
takes is thresholded, cached, logged, and replayable.

All backends run either offline (``StaticBackend``) or against a *localhost*
model server (``BasalOmniBackend``). The remote ``JevBackend`` exists for
completeness but Aegis defaults to ``local_only`` (see :mod:`aegis.config`).
"""

from .client import (
    BasalOmniBackend,
    BooleanResult,
    ChoiceResult,
    DecisionBackend,
    DecisionClient,
    DecisionError,
    JevBackend,
    LLMJudgeBackend,
    ScoreResult,
    StaticBackend,
)
from .router import DecisionRouter, RouterMetrics

__all__ = [
    "BasalOmniBackend",
    "BooleanResult",
    "ChoiceResult",
    "DecisionBackend",
    "DecisionClient",
    "DecisionError",
    "JevBackend",
    "LLMJudgeBackend",
    "ScoreResult",
    "StaticBackend",
    "DecisionRouter",
    "RouterMetrics",
]
