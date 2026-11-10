"""Compatibility shim — promoted into :mod:`aegis.knowledge`."""

from aegis.knowledge.base import KnowledgeBase as PipelineResult  # noqa: F401
from aegis.knowledge.models import (  # noqa: F401
    Candidate,
    Finding as ReportFinding,
    Rejection,
)

__all__ = ["Candidate", "ReportFinding", "Rejection", "PipelineResult"]
