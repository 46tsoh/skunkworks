"""Data model for the triage pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Candidate:
    """A candidate security finding fed into the pipeline (Strix-style).

    ``hints`` is POC-only ground truth used by the offline stand-in backend to
    produce deterministic decisions; real backends (basal-omni/Jev) read the
    natural-language statements and ignore it.
    """

    id: str
    title: str
    cwe: str
    component: str
    cvss_vector: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    hints: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportFinding:
    """An accepted finding, after triage/hypothesis/dedup/validation/scoring."""

    candidate: Candidate
    posterior: float
    cvss_score: float
    severity: str
    exploitable: bool
    stages_passed: int
    failed_stage: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.candidate.id,
            "title": self.candidate.title,
            "cwe": self.candidate.cwe,
            "component": self.candidate.component,
            "cvss_vector": self.candidate.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "posterior": round(self.posterior, 3),
            "exploitable": self.exploitable,
            "stages_passed": self.stages_passed,
            "failed_stage": self.failed_stage,
        }


@dataclass
class Rejection:
    """A candidate dropped by the pipeline, with the stage and reason."""

    candidate: Candidate
    stage: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.candidate.id,
            "title": self.candidate.title,
            "stage": self.stage,
            "reason": self.reason,
        }


@dataclass
class PipelineResult:
    accepted: list[ReportFinding] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": [f.as_dict() for f in self.accepted],
            "rejected": [r.as_dict() for r in self.rejected],
            "metrics": self.metrics,
        }
