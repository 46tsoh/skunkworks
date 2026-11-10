"""Autonomous red-team engine (scope-gated offensive actions).

See docs/specs/red-team-engine.md. Stage 1 is the authorization foundation:
:mod:`aegis.redteam.scope` loads an engagement scope file and refuses any
offensive action against a target that is not explicitly in scope.
"""

from aegis.redteam.scope import (
    EngagementScope,
    ScopeDecision,
    ScopeError,
    load_scope,
)
from aegis.redteam.engine import ExploitResult, RedTeamEngine
from aegis.redteam.postexploit import PostExploitResult, retrieve_flag

__all__ = [
    "EngagementScope", "ScopeDecision", "ScopeError", "load_scope",
    "RedTeamEngine", "ExploitResult", "PostExploitResult", "retrieve_flag",
]
