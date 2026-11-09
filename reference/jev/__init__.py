"""Provider-agnostic typed-decision layer for LLM security agents.

See ``docs/jev-security-agent-integration.md`` for the design rationale.
"""

from .decision_client import (
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
