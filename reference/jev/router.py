"""Compatibility shim — promoted into :mod:`aegis.decision.router`."""

from aegis.decision.router import DecisionRouter, RouterMetrics  # noqa: F401

__all__ = ["DecisionRouter", "RouterMetrics"]
