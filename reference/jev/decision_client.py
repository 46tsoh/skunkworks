"""Compatibility shim — promoted into :mod:`aegis.decision.client`.

The real implementation now lives in the ``aegis`` package. This module
re-exports it so existing imports (and the research docs) keep working.
"""

from aegis.decision.client import (  # noqa: F401
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

__all__ = [
    "BasalOmniBackend", "BooleanResult", "ChoiceResult", "DecisionBackend",
    "DecisionClient", "DecisionError", "JevBackend", "LLMJudgeBackend",
    "ScoreResult", "StaticBackend",
]
