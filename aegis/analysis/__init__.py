"""Aegis analysis pipeline: triage -> hypothesis -> dedupe -> validate -> CVSS."""

from . import cvss
from .backends import HintBackend, build_router
from .pipeline import run

__all__ = ["cvss", "HintBackend", "build_router", "run"]
