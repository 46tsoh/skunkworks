"""Unified knowledge model shared by both Aegis engines.

A :class:`Candidate` is a raw potential finding fed into the pipeline (from any
scanner/engine). A :class:`Finding` is an accepted, scored, triaged result; a
:class:`Rejection` records a candidate the pipeline dropped and why. Both
engines — the Strix-style dynamic loop and the RAPTOR-style static/audit loop —
produce ``Candidate`` objects and read/write :class:`Finding` objects in one
shared :class:`~aegis.knowledge.base.KnowledgeBase`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """CVSS v3.1 qualitative severity bands (ordered)."""

    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.NONE,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# Minimal CWE -> OWASP Top 10 (2021) mapping for classification. Extendable;
# unmatched CWEs fall through to ``None``.
_CWE_TO_OWASP = {
    "CWE-89": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-77": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-284": "A01:2021-Broken Access Control",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-311": "A02:2021-Cryptographic Failures",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-918": "A10:2021-Server-Side Request Forgery",
    "CWE-611": "A05:2021-Security Misconfiguration",
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",
}


def owasp_for_cwe(cwe: str) -> Optional[str]:
    """Return the OWASP Top-10 (2021) category for a CWE id, or None."""
    return _CWE_TO_OWASP.get(cwe.strip().upper())


@dataclass
class Candidate:
    """A candidate security finding fed into the pipeline.

    ``hints`` is sample/offline ground truth used only by the deterministic
    stand-in backend; real backends read the natural-language statements and
    ignore it. ``source_engine`` records which engine surfaced the candidate
    (``dynamic`` / ``static`` / a tool name) so the unified report can show
    provenance.
    """

    id: str
    title: str
    cwe: str
    component: str
    cvss_vector: str
    description: str = ""
    evidence: list = field(default_factory=list)
    hints: dict = field(default_factory=dict)
    source_engine: str = "unknown"
    metadata: dict = field(default_factory=dict)

    @property
    def owasp(self) -> Optional[str]:
        return owasp_for_cwe(self.cwe)


@dataclass
class Finding:
    """An accepted finding after triage / hypothesis / dedup / validate / score."""

    candidate: Candidate
    posterior: float
    cvss_score: float
    severity: str
    exploitable: bool
    stages_passed: int
    failed_stage: Optional[str] = None

    @property
    def id(self) -> str:
        return self.candidate.id

    @property
    def title(self) -> str:
        return self.candidate.title

    @property
    def owasp(self) -> Optional[str]:
        return self.candidate.owasp

    @property
    def source_engine(self) -> str:
        return self.candidate.source_engine

    def as_dict(self) -> dict:
        return {
            "id": self.candidate.id,
            "title": self.candidate.title,
            "cwe": self.candidate.cwe,
            "owasp": self.candidate.owasp,
            "component": self.candidate.component,
            "cvss_vector": self.candidate.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "posterior": round(self.posterior, 3),
            "exploitable": self.exploitable,
            "stages_passed": self.stages_passed,
            "failed_stage": self.failed_stage,
            "source_engine": self.candidate.source_engine,
            "evidence": list(self.candidate.evidence),
        }


# Backwards-compatible alias: the POC called accepted findings ``ReportFinding``.
ReportFinding = Finding


@dataclass
class Rejection:
    """A candidate dropped by the pipeline, with the stage and reason."""

    candidate: Candidate
    stage: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "id": self.candidate.id,
            "title": self.candidate.title,
            "stage": self.stage,
            "reason": self.reason,
        }


__all__ = [
    "Severity",
    "Candidate",
    "Finding",
    "ReportFinding",
    "Rejection",
    "owasp_for_cwe",
]
