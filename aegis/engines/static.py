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
from aegis.engines.base import EngineReport, _candidates_from_tools
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
                 priority_min: float = 0.0, registry=None,
                 tool_names: Optional[Sequence[str]] = None,
                 planner=None, event_sink=None) -> None:
        self._providers = list(providers) if providers else [HintEvidenceProvider()]
        self._priority_min = priority_min
        self._registry = registry
        self._tool_names = tool_names
        self._tool_runs: list = []
        self._planner = planner
        from aegis.engines.events import NullSink
        self._events = event_sink or NullSink()
        self.hypotheses: List[Hypothesis] = []
        self.coverage = CoverageLedger()

    def set_planner(self, planner) -> None:
        self._planner = planner

    def set_event_sink(self, sink) -> None:
        self._events = sink

    def _turn(self, task: str, state: str) -> dict:
        """One researcher turn: generative when a planner is present, else a
        deterministic scripted narration (keeps offline runs reproducible)."""
        if self._planner is not None:
            from aegis.llm import agent_turn
            return agent_turn(self._planner, "researcher", task, state,
                              ["investigate this hypothesis", "defer"])
        return {"assistant": f"Researcher: {task}.",
                "think": f"state — {state}", "action_index": 0, "rationale": ""}

    def available(self) -> bool:
        return True

    def enumerate_candidates(self, target: str,
                             config: AegisConfig) -> Sequence[Candidate]:
        if self._registry is not None:
            cands, self._tool_runs = _candidates_from_tools(
                self._registry, self.kind, target, self._tool_names)
            return cands
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

        # A single RAPTOR-style researcher agent works the hypothesis queue.
        ev = self._events
        ev.emit("s0001", "spawn", role="researcher",
                task="hypothesis-driven static audit", parent_id=None)
        ev.emit("s0001", "status", status="running")

        # Seed hypotheses, each scored for priority (a typed score decision).
        self.hypotheses = []
        self.coverage = CoverageLedger()
        stage_counts = {"triage": 0, "hypothesis": 0, "dedupe": 0,
                        "validated_exploitable": 0, "validated_informational": 0,
                        "priority": 0}
        for seq, cand in enumerate(candidates):
            score = router.score(
                "static.hypothesis.priority",
                f"Rate how worth investigating this hypothesis is: "
                f"{cand.title} ({cand.cwe}) in {cand.component}. [ref={cand.id}]",
                0.0, 10.0,
            )
            priority = score.value
            ev.emit("s0001", "decision", kind="hypothesis.priority",
                    outcome=f"{priority:.1f}/10", probability=None,
                    backend=score.backend)
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
            # The researcher takes a generative turn on this hypothesis.
            turn = self._turn(f"investigate {cand.title}",
                              f"{cand.title} ({cand.cwe}) in {cand.component}, "
                              f"priority {hyp.priority:.1f}/10")
            ev.emit("s0001", "assistant", text=turn["assistant"])
            if turn["think"]:
                ev.emit("s0001", "think", text=turn["think"])
            # Gather + record evidence/coverage (a tool call, with arguments).
            for provider in self._providers:
                ev.emit("s0001", "tool_call", tool=provider.name,
                        args={"component": cand.component, "ref": cand.id})
                evidence = provider.gather(hyp)
                self.coverage.mark(cand.component, provider.name)
                ev.emit("s0001", "tool_output", tool=provider.name, status="ok",
                        summary=f"{len(evidence)} evidence item(s)",
                        count=len(evidence))
            # Triage gate.
            tp = is_true_positive(router, cand)
            ev.emit("s0001", "decision", kind="triage.true_positive",
                    outcome="true_positive" if tp else "false_positive")
            if not tp:
                kb.add_rejection(cand, "triage", "likely false positive")
                hyp.status = HypothesisStatus.REJECTED
                stage_counts["triage"] += 1
                continue
            # Shared promotion path (posterior -> dedupe -> validate -> score).
            outcome = promote_candidate(router, cand, kb.accepted,
                                        config.posterior_min)
            if outcome.finding is not None:
                # The researcher writes why it matters (generative modes).
                if self._planner is not None:
                    from aegis.llm import explain_finding
                    rationale = explain_finding(self._planner, cand.title,
                                                cand.evidence)
                    if rationale:
                        outcome.finding.rationale = rationale
                kb.add_finding(outcome.finding)
                hyp.status = HypothesisStatus.ACCEPTED
                key = ("validated_exploitable" if outcome.exploitable
                       else "validated_informational")
                stage_counts[key] += 1
                if outcome.finding.rationale:
                    ev.emit("s0001", "assistant", text=outcome.finding.rationale)
                ev.emit("s0001", "finding", id=cand.id, title=cand.title,
                        severity=outcome.finding.severity,
                        exploitable=outcome.exploitable)
            else:
                kb.rejected.append(outcome.rejection)
                hyp.status = HypothesisStatus.REJECTED
                stage_counts[outcome.stage] += 1

        ev.emit("s0001", "status", status="completed")
        ev.emit("s0001", "finish",
                summary=f"{len([h for h in self.hypotheses if h.status.value == 'accepted'])} hypotheses confirmed")
        kb.rank()
        return EngineReport(
            name=self.name, kind=self.kind, available=True, ran=True,
            candidates=len(candidates), accepted=len(kb.accepted),
            rejected=len(kb.rejected), stage_counts=stage_counts,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            extra={"hypotheses": [h.as_dict() for h in self.hypotheses],
                   "coverage": self.coverage.summary(),
                   "tool_runs": self._tool_runs,
                   "degraded": any(r["status"] not in ("ok",)
                                   for r in self._tool_runs)},
        )


__all__ = ["StaticEngine", "Hypothesis", "HypothesisStatus", "CoverageLedger",
           "HintEvidenceProvider"]
