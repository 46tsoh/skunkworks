"""Compatibility shim — promoted into :mod:`aegis.analysis.validate`."""

from aegis.analysis.validate import ValidationResult, validate_exploitability  # noqa: F401

__all__ = ["ValidationResult", "validate_exploitability"]
