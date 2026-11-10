"""Aegis — a unified, local-only security-analysis framework.

Aegis promotes two research artifacts into one real package:

* a provider-agnostic typed **decision layer** (:mod:`aegis.decision`), and
* a combined **analysis pipeline** (:mod:`aegis.analysis`) that routes
  Strix-style triage/dedup/CVSS and RAPTOR-style hypothesis/validation through
  that layer,

sharing one :class:`~aegis.knowledge.base.KnowledgeBase`. Everything runs
offline or against localhost model servers; nothing is hosted or sent to a
third-party service by default (see :class:`aegis.config.AegisConfig`).
"""

from __future__ import annotations

__version__ = "0.1.0"

from aegis.config import AegisConfig
from aegis.decision import DecisionRouter
from aegis.knowledge import Candidate, Finding, KnowledgeBase, Rejection

__all__ = [
    "__version__",
    "AegisConfig",
    "DecisionRouter",
    "Candidate",
    "Finding",
    "KnowledgeBase",
    "Rejection",
]
