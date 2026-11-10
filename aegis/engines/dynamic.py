"""DynamicEngine — Strix-style graph-of-agents loop (offline, deterministic).

See `docs/specs/dynamic-engine.md`. A small set of specialist agent roles share
one blackboard and take bounded steps against a local/sample target. Which
action fires next is a routing decision through ``DecisionRouter.choose``; each
raw candidate is triaged with ``DecisionRouter.gate`` before the shared
promotion stages add a ``Finding`` to the shared ``KnowledgeBase``. Tool-agnostic:
offline, a ``SampleProbe`` stands in for the M3 dynamic tools.
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


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"


@dataclass
class AgentNode:
    id: str
    role: AgentRole
    task: str
    parent_id: Optional[str] = None
    status: AgentStatus = AgentStatus.PENDING
    steps_spent: int = 0

    def as_dict(self) -> dict:
        return {"id": self.id, "role": self.role.value, "task": self.task,
                "parent_id": self.parent_id, "status": self.status.value,
                "steps_spent": self.steps_spent}


@dataclass
class StepBudget:
    max_steps: int = 64
    steps_spent: int = 0

    def exhausted(self) -> bool:
        return self.steps_spent >= self.max_steps


class SampleProbe:
    """Offline stand-in for a dynamic tool: yields the sample candidates."""

    def __init__(self, candidates: Sequence[Candidate]) -> None:
        self._candidates = list(candidates)

    def surfaces(self) -> List[str]:
        return [c.component for c in self._candidates]

    def probe(self, surface: str) -> List[Candidate]:
        return [c for c in self._candidates if c.component == surface]


class DynamicEngine:
    """Strix-style dynamic engine conforming to the Orchestrator Engine protocol."""

    name = "dynamic"
    kind = "dynamic"

    def __init__(self, probe: Optional[SampleProbe] = None,
                 max_steps: int = 64) -> None:
        self._probe = probe
        self._max_steps = max_steps
        self.graph: List[AgentNode] = []

    def available(self) -> bool:
        return True

    def enumerate_candidates(self, target: str,
                             config: AegisConfig) -> Sequence[Candidate]:
        path = Path(target or _DEFAULT_TARGET)
        if path.is_dir():
            path = path / "candidates_dynamic.json"
        if not path.exists():
            return []
        return load_candidates(path, source_engine=self.kind)

    # -- the graph-of-agents loop ---------------------------------------- #
    def run(self, target: str, kb: KnowledgeBase, router: DecisionRouter,
            config: AegisConfig) -> EngineReport:
        t0 = time.perf_counter()
        candidates = list(self.enumerate_candidates(target, config))
        probe = self._probe or SampleProbe(candidates)

        # Seed the agent graph: a coordinator root with recon + exploitation.
        coordinator = AgentNode("a0001", AgentRole.COORDINATOR, "drive the test",
                                status=AgentStatus.RUNNING)
        recon = AgentNode("a0002", AgentRole.RECON, "map surfaces", "a0001",
                          AgentStatus.RUNNING)
        exploit = AgentNode("a0003", AgentRole.EXPLOITATION, "confirm leads",
                            "a0001", AgentStatus.RUNNING)
        self.graph = [coordinator, recon, exploit]

        budget = StepBudget(max_steps=max(self._max_steps, 4 * len(candidates) + 8))
        unprobed = list(probe.surfaces())
        pending: List[Candidate] = []
        seen_surfaces = set()
        stage_counts = {"triage": 0, "hypothesis": 0, "dedupe": 0,
                        "validated_exploitable": 0, "validated_informational": 0}

        while not budget.exhausted():
            # Build the state-ordered action set; option 0 is the sensible next
            # action, so routing through choose() is logged yet deterministic.
            if unprobed:
                options = [f"probe:{unprobed[0]}", "finish"]
            elif pending:
                options = [f"triage:{pending[0].id}", "finish"]
            else:
                options = ["finish"]
            action = router.choose("dynamic.route_next_action",
                                   self._context(kb, unprobed, pending),
                                   options).option
            budget.steps_spent += 1

            if action.startswith("probe:"):
                surface = action.split(":", 1)[1]
                unprobed = [s for s in unprobed if s != surface]
                if surface in seen_surfaces:
                    continue
                seen_surfaces.add(surface)
                found = probe.probe(surface)
                pending.extend(found)
                recon.steps_spent += 1
            elif action.startswith("triage:"):
                cand = pending.pop(0)
                exploit.steps_spent += 1
                # 1. triage gate (cheap, before promotion)
                if not is_true_positive(router, cand):
                    kb.add_rejection(cand, "triage", "likely false positive")
                    stage_counts["triage"] += 1
                    continue
                # 2-5. shared promotion path
                outcome = promote_candidate(router, cand, kb.accepted,
                                            config.posterior_min)
                if outcome.finding is not None:
                    kb.add_finding(outcome.finding)
                    key = ("validated_exploitable" if outcome.exploitable
                           else "validated_informational")
                    stage_counts[key] += 1
                else:
                    kb.rejected.append(outcome.rejection)
                    stage_counts[outcome.stage] += 1
            else:  # finish
                break

        for node in self.graph:
            node.status = AgentStatus.COMPLETED
        kb.rank()

        return EngineReport(
            name=self.name, kind=self.kind, available=True, ran=True,
            candidates=len(candidates), accepted=len(kb.accepted),
            rejected=len(kb.rejected), stage_counts=stage_counts,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            extra={"graph": [n.as_dict() for n in self.graph],
                   "steps_spent": budget.steps_spent},
        )

    @staticmethod
    def _context(kb: KnowledgeBase, unprobed, pending) -> str:
        return (f"surfaces_left={len(unprobed)} pending={len(pending)} "
                f"accepted={len(kb.accepted)}")


__all__ = ["DynamicEngine", "SampleProbe", "AgentNode", "AgentRole",
           "AgentStatus", "StepBudget"]
