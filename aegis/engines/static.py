"""StaticEngine — RAPTOR-style hypothesis-driven audit loop (offline).

See `docs/specs/static-engine.md`. Each candidate becomes a hypothesis; a
priority score (``DecisionRouter.score``) orders a deterministic queue; the
highest-priority hypothesis is investigated (triage gate, then the shared
promotion stages: posterior -> dedupe -> validate -> score); a coverage ledger
records what was examined. Tool-agnostic: offline, a ``HintEvidenceProvider``
derives evidence from the candidate itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence

from aegis.analysis.pipeline import promote_candidate
from aegis.analysis.triage import is_true_positive
from aegis.config import DEFAULT_POSTERIOR_MIN, AegisConfig
from aegis.decision import DecisionRouter
from aegis.engines.base import EngineReport
from aegis.knowledge.base import KnowledgeBase
from aegis.knowledge.loader import load_candidates
from aegis.knowledge.models import Candidate, Finding

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_TARGET = _REPO_ROOT / "data" / "sample_target"


class HypothesisStatus(str, Enum):
    QUEUED = "queued"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class Hypothesis:
    candidate: Candidate
    seq: int
    priority: float = 0.0
    status: HypothesisStatus = HypothesisStatus.QUEUED

    @property
    def id(self) -> str:
        return self.candidate.id

    def as_dict(self) -> dict:
        return {"id": self.id, "seq": self.seq,
                "priority": round(self.priority, 3), "status": self.status.value}


@dataclass
class CoverageLedger:
    examined: dict = field(default_factory=dict)  # component -> set(tool labels)

    def mark(self, component: str, label: str) -> None:
        self.examined.setdefault(component, set()).add(label)

    def summary(self) -> dict:
        return {"examined": len(self.examined),
                "components": sorted(self.examined)}


class HintEvidenceProvider:
    """Offline evidence provider: surfaces the candidate's own evidence."""

    name = "static:hint"

    def gather(self, hyp: Hypothesis) -> list:
        return list(hyp.candidate.evidence)


class StaticEngine:
    """RAPTOR-style static engine conforming to the Orchestrator Engine protocol."""

    name = "static"
    kind = "static"

    def __init__(self, providers: Optional[Sequence] = None,
                 priority_min: float = 0.0) -> None:
        self._providers = list(providers) if providers else [HintEvidenceProvider()]
        self._priority_min = priority_min
        self.hypotheses: List[Hypothesis] = []
        self.coverage = CoverageLedger()

    def available(self) -> bool:
        return True

    def enumerate_candidates(self, target: str,
                             config: AegisConfig) -> Sequence[Candidate]:
        path = Path(target or _DEFAULT_TARGET)
        if path.is_dir():
            path = path / "candidates_static.json"
        if not path.exists():
            return []
        return load_candidates(path, source_engine=self.kind)

    def run(self, target: str, kb: KnowledgeBase, router: DecisionRouter,
            config: AegisConfig) -> EngineReport:
        t0 = time.perf_counter()
        candidates = list(self.enumerate_candidates(target, config))

        # Seed hypotheses, each scored for priority (a typed score decision).
        self.hypotheses = []
        self.coverage = CoverageLedger()
        stage_counts = {"triage": 0, "hypothesis": 0, "dedupe": 0,
                        "validated_exploitable": 0, "validated_informational": 0,
                        "priority": 0}
        for seq, cand in enumerate(candidates):
            priority = router.score(
                "static.hypothesis.priority",
                f"Rate how worth investigating this hypothesis is: "
                f"{cand.title} ({cand.cwe}) in {cand.component}. [ref={cand.id}]",
                0.0, 10.0,
            ).value
            hyp = Hypothesis(cand, seq, priority)
            if priority < self._priority_min:
                kb.add_rejection(cand, "priority", f"priority {priority:.2f} below floor")
                hyp.status = HypothesisStatus.REJECTED
                stage_counts["priority"] += 1
            self.hypotheses.append(hyp)

        # Deterministic total order: priority desc, then seq asc.
        queue = sorted(
            [h for h in self.hypotheses if h.status == HypothesisStatus.QUEUED],
            key=lambda h: (-h.priority, h.seq),
        )

        for hyp in queue:
            cand = hyp.candidate
            # Gather + record evidence/coverage.
            for provider in self._providers:
                provider.gather(hyp)
                self.coverage.mark(cand.component, provider.name)
            # Triage gate.
            if not is_true_positive(router, cand):
                kb.add_rejection(cand, "triage", "likely false positive")
                hyp.status = HypothesisStatus.REJECTED
                stage_counts["triage"] += 1
                continue
            # Shared promotion path (posterior -> dedupe -> validate -> score).
            outcome = promote_candidate(router, cand, kb.accepted,
                                        config.posterior_min)
            if outcome.finding is not None:
                kb.add_finding(outcome.finding)
                hyp.status = HypothesisStatus.ACCEPTED
                key = ("validated_exploitable" if outcome.exploitable
                       else "validated_informational")
                stage_counts[key] += 1
            else:
                kb.rejected.append(outcome.rejection)
                hyp.status = HypothesisStatus.REJECTED
                stage_counts[outcome.stage] += 1

        kb.rank()
        return EngineReport(
            name=self.name, kind=self.kind, available=True, ran=True,
            candidates=len(candidates), accepted=len(kb.accepted),
            rejected=len(kb.rejected), stage_counts=stage_counts,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            extra={"hypotheses": [h.as_dict() for h in self.hypotheses],
                   "coverage": self.coverage.summary()},
        )


__all__ = ["StaticEngine", "Hypothesis", "HypothesisStatus", "CoverageLedger",
           "HintEvidenceProvider"]
