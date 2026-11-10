"""The shared findings knowledge base.

Both engines write here and the unified report reads from here. A
:class:`KnowledgeBase` collects accepted :class:`Finding` objects and
:class:`Rejection` records, ranks findings consistently (exploitable first,
then CVSS, then posterior), and answers queries by severity / OWASP / engine.

It also carries the run ``metrics`` dict and serializes to a single ``as_dict``
payload — the one artifact the dashboard and the ``report.json`` file consume.
It intentionally preserves the POC ``PipelineResult`` surface (``.accepted`` /
``.rejected`` / ``.metrics`` / ``.as_dict``) so it is a drop-in result object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Candidate, Finding, Rejection, Severity


@dataclass
class KnowledgeBase:
    """Shared store of accepted findings and rejections for one run."""

    accepted: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    # -- mutation --------------------------------------------------------- #
    def add_finding(self, finding: Finding) -> None:
        self.accepted.append(finding)

    def add_rejection(self, candidate: Candidate, stage: str, reason: str) -> None:
        self.rejected.append(Rejection(candidate, stage, reason))

    # -- ranking / queries ------------------------------------------------ #
    def rank(self) -> list:
        """Sort accepted findings in place: exploitable, CVSS, posterior."""
        self.accepted.sort(
            key=lambda f: (f.exploitable, f.cvss_score, f.posterior),
            reverse=True,
        )
        return self.accepted

    def by_severity(self, severity) -> list:
        name = severity.value if isinstance(severity, Severity) else str(severity)
        return [f for f in self.accepted if f.severity == name]

    def by_engine(self, engine: str) -> list:
        return [f for f in self.accepted if f.source_engine == engine]

    def by_owasp(self, category: str) -> list:
        return [f for f in self.accepted if f.owasp == category]

    def find(self, finding_id: str) -> Optional[Finding]:
        for f in self.accepted:
            if f.id == finding_id:
                return f
        return None

    # -- aggregates ------------------------------------------------------- #
    def severity_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.accepted:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def engine_counts(self) -> dict:
        counts: dict = {}
        for f in self.accepted:
            counts[f.source_engine] = counts.get(f.source_engine, 0) + 1
        return counts

    def merge(self, other: "KnowledgeBase") -> None:
        """Fold another knowledge base (e.g. a second engine's) into this one."""
        self.accepted.extend(other.accepted)
        self.rejected.extend(other.rejected)

    # -- serialization ---------------------------------------------------- #
    def as_dict(self) -> dict:
        return {
            "accepted": [f.as_dict() for f in self.accepted],
            "rejected": [r.as_dict() for r in self.rejected],
            "metrics": self.metrics,
            "summary": {
                "severity_counts": self.severity_counts(),
                "engine_counts": self.engine_counts(),
            },
        }


# Backwards-compatible alias: the POC returned a ``PipelineResult``.
PipelineResult = KnowledgeBase

__all__ = ["KnowledgeBase", "PipelineResult"]
