"""Compatibility shim — promoted into :mod:`aegis.analysis.dedupe`."""

from aegis.analysis.dedupe import find_duplicate  # noqa: F401

__all__ = ["find_duplicate"]
