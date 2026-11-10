"""Compatibility shim — promoted into :mod:`aegis.analysis.cvss`."""

from aegis.analysis.cvss import (  # noqa: F401
    base_score,
    parse_vector,
    severity_band,
)

__all__ = ["base_score", "parse_vector", "severity_band"]
