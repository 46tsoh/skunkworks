"""Compatibility shim — promoted into ``aegis.decision.integrations.raptor_gates``."""

from aegis.decision.integrations.raptor_gates import (  # noqa: F401
    RAPTOR_VALIDATE_THRESHOLDS,
    RaptorValidateChain,
    ValidationResult,
)

__all__ = ["RAPTOR_VALIDATE_THRESHOLDS", "RaptorValidateChain", "ValidationResult"]
