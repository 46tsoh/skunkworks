"""Compatibility shim — promoted into ``aegis.decision.integrations.strix_decisions``."""

from aegis.decision.integrations.strix_decisions import (  # noqa: F401
    STRIX_THRESHOLDS,
    Finding,
    StrixDecisions,
)

__all__ = ["STRIX_THRESHOLDS", "Finding", "StrixDecisions"]
