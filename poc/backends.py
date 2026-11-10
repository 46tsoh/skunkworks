"""Compatibility shim — promoted into :mod:`aegis.analysis.backends`."""

from aegis.analysis.backends import HintBackend, build_router  # noqa: F401
from aegis.config import DEFAULT_POSTERIOR_MIN as POSTERIOR_MIN  # noqa: F401
from aegis.config import DEFAULT_THRESHOLDS as POC_THRESHOLDS  # noqa: F401
from aegis.decision.client import StaticBackend  # noqa: F401

__all__ = ["HintBackend", "build_router", "POC_THRESHOLDS", "POSTERIOR_MIN",
           "StaticBackend"]
