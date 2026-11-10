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
    # Ordered record of what this agent actually did, step by step. Each entry
    # is {"seq": int, "kind": str, "label": str, "detail": str, "tone": str}.
    trajectory: List[dict] = field(default_factory=list)

    def log(self, seq: int, kind: str, label: str, detail: str = "",
            tone: str = "neutral") -> None:
        self.trajectory.append({"seq": seq, "kind": kind, "label": label,
                                "detail": detail, "tone": tone})

    def as_dict(self) -> dict:
        return {"id": self.id, "role": self.role.value, "task": self.task,
                "parent_id": self.parent_id, "status": self.status.value,
                "steps_spent": self.steps_spent, "trajectory": self.trajectory}


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

    def tool_info(self, surface: str):
        return "recon.probe", {"surface": surface}

    def status(self, surface: str) -> str:
        return "ok"


def _grouped_tool_results(registry, kind_str: str, target: str,
                          tool_names=None) -> list:
    """Run each available tool once, keeping its results grouped by tool (so the
    agent can select tools one at a time with real names, args and status)."""
    from aegis.tools.base import ToolKind
    kind = ToolKind(kind_str)
    if tool_names:
        tools = [registry.get(n) for n in tool_names
                 if registry.get(n).kind == kind and registry.get(n).available()]
    else:
        tools = registry.available(kind)
    out = []
    for tool in tools:
        result = tool.run(target)
        for c in result.candidates:
            c.source_engine = kind_str
        out.append({"tool": result.tool,
                    "args": {"target": str(target) or "sample-target"},
                    "status": result.status.value,
                    "errors": list(result.errors),
                    "candidates": list(result.candidates) if result.ok else []})
    return out


class RegistryProbe:
    """Agent-selectable view over real tool adapters: each 'surface' is a tool.

    Selecting a tool reveals its (already-run) candidates and the real tool name,
    arguments and status, so the transcript shows genuine adapter calls.
    """

    def __init__(self, grouped: Sequence[dict]) -> None:
        self._order = [g["tool"] for g in grouped]
        self._by = {g["tool"]: g for g in grouped}

    def surfaces(self) -> List[str]:
        return list(self._order)

    def probe(self, label: str) -> List[Candidate]:
        return list(self._by.get(label, {}).get("candidates", []))

    def tool_info(self, label: str):
        return label, self._by.get(label, {}).get("args", {})

    def status(self, label: str) -> str:
        return self._by.get(label, {}).get("status", "ok")


class DynamicEngine:
    """Strix-style dynamic engine conforming to the Orchestrator Engine protocol."""

    name = "dynamic"
    kind = "dynamic"

    def __init__(self, probe: Optional[SampleProbe] = None,
                 max_steps: int = 64, registry=None,
                 tool_names: Optional[Sequence[str]] = None,
                 planner=None, event_sink=None) -> None:
        self._probe = probe
        self._max_steps = max_steps
        self._registry = registry
        self._tool_names = tool_names
        self._tool_runs: list = []
        self._grouped: Optional[list] = None  # cached per-tool results (registry)
        self._planner = planner  # generative LLM (full-llm / llm+decision modes)
        from aegis.engines.events import NullSink
        self._events = event_sink or NullSink()
        self.graph: List[AgentNode] = []

    def set_planner(self, planner) -> None:
        """Inject the generative LLM that plans/writes (modes wire this in)."""
        self._planner = planner

    def set_event_sink(self, sink) -> None:
        """Inject the live transcript sink (the Orchestrator wires this in)."""
        self._events = sink

    def _turn(self, role: str, task: str, state: str, options: Sequence[str]) -> dict:
        """One agent turn: generative when a planner is present, else a
        deterministic scripted narration (keeps offline runs reproducible)."""
        if self._planner is not None and len(options) > 1:
            from aegis.llm import agent_turn
            return agent_turn(self._planner, role, task, state, options)
        # Deterministic scripted turn — option 0 is the sensible next action.
        act = options[0] if options else "finish"
        verb = ("mapping the next attack surface" if act.startswith("probe")
                else "triaging the next lead" if act.startswith("triage")
                else "no work left; finishing")
        return {"assistant": f"{role.capitalize()}: {verb}.",
                "think": f"state — {state}", "action_index": 0, "rationale": ""}

    def available(self) -> bool:
        return True

    def enumerate_candidates(self, target: str,
                             config: AegisConfig) -> Sequence[Candidate]:
        if self._registry is not None:
            # Run each tool once, keep results grouped so the agent can select
            # tools one at a time in the loop; flatten for router seeding.
            self._grouped = _grouped_tool_results(
                self._registry, self.kind, target, self._tool_names)
            self._tool_runs = [{"name": g["tool"], "status": g["status"],
                                "errors": g["errors"],
                                "candidates": len(g["candidates"])}
                               for g in self._grouped]
            return [c for g in self._grouped for c in g["candidates"]]
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
        # With a registry, the agent selects real tools (RegistryProbe); offline
        # it probes the sample surfaces.
        if self._probe is not None:
            probe = self._probe
        elif self._grouped is not None:
            probe = RegistryProbe(self._grouped)
        else:
            probe = SampleProbe(candidates)

        # Seed the agent graph: a coordinator root with recon + exploitation.
        coordinator = AgentNode("a0001", AgentRole.COORDINATOR, "drive the test",
                                status=AgentStatus.RUNNING)
        recon = AgentNode("a0002", AgentRole.RECON, "map surfaces", "a0001",
                          AgentStatus.RUNNING)
        exploit = AgentNode("a0003", AgentRole.EXPLOITATION, "confirm leads",
                            "a0001", AgentStatus.RUNNING)
        self.graph = [coordinator, recon, exploit]
        ev = self._events
        # The coordinator opens the test and its two specialists are spawned.
        ev.emit("a0001", "spawn", role="coordinator", task="drive the test",
                parent_id=None)
        ev.emit("a0001", "status", status="running")
        for node in (recon, exploit):
            ev.emit(node.id, "spawn", role=node.role.value, task=node.task,
                    parent_id="a0001")
            ev.emit("a0001", "message", to=node.id,
                    text=f"You are {node.role.value}: {node.task}.")

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
            state = self._context(kb, unprobed, pending)

            # 1. PLAN/WRITE — the coordinator takes a generative turn: assistant
            #    prose + a private think note + its proposed action. Offline this
            #    is a deterministic scripted turn, so the loop stays reproducible.
            budget.steps_spent += 1
            seq = budget.steps_spent
            turn = self._turn("coordinator", "drive the test", state, options)
            ev.emit("a0001", "assistant", text=turn["assistant"])
            if turn["think"]:
                ev.emit("a0001", "think", text=turn["think"])
            idx = turn["action_index"]
            if idx:  # surface the planner's choice first
                options = [options[idx]] + options[:idx] + options[idx + 1:]
            if self._planner is not None and len(options) > 1:
                coordinator.log(seq, "plan", f"plan → {options[0]}",
                                turn["rationale"] or turn["assistant"])

            # 2. DECIDE — the decision model (or the LLM, in full-llm mode)
            #    commits one action through the shared router.
            choice = router.choose("dynamic.route_next_action", state, options)
            action = choice.option
            ev.emit("a0001", "decision", kind="route_next_action",
                    outcome=action, probability=round(choice.probability, 3),
                    backend=choice.backend)

            if action.startswith("probe:"):
                surface = action.split(":", 1)[1]
                coordinator.log(seq, "route", f"delegate recon → {surface}",
                                f"routed among {len(options)} options")
                ev.emit("a0001", "message", to="a0002", text=f"Map {surface}.")
                unprobed = [s for s in unprobed if s != surface]
                if surface in seen_surfaces:
                    recon.log(seq, "probe", surface, "already mapped", "muted")
                    continue
                seen_surfaces.add(surface)
                # 3. ACT — the recon agent runs a tool, with arguments, and reads
                #    its output (the real adapter when wired; the sample probe else).
                tool_name, tool_args = probe.tool_info(surface)
                ev.emit("a0002", "tool_call", tool=tool_name, args=tool_args)
                found = probe.probe(surface)
                pending.extend(found)
                recon.steps_spent += 1
                titles = ", ".join(c.title for c in found) or "nothing"
                ev.emit("a0002", "tool_output", tool=tool_name,
                        status=probe.status(surface),
                        summary=f"surfaced {len(found)} lead(s): {titles}",
                        count=len(found))
                recon.log(seq, "probe", surface,
                          f"surfaced {len(found)} lead(s): {titles}",
                          "found" if found else "muted")
            elif action.startswith("triage:"):
                cand = pending.pop(0)
                exploit.steps_spent += 1
                coordinator.log(seq, "route", f"delegate exploit → {cand.title}",
                                f"routed among {len(options)} options")
                ev.emit("a0001", "message", to="a0003",
                        text=f"Confirm the lead: {cand.title}.")
                eturn = self._turn("exploitation", "confirm leads",
                                   f"evaluating {cand.title} ({cand.component})",
                                   ["triage this lead", "skip"])
                ev.emit("a0003", "assistant", text=eturn["assistant"])
                if eturn["think"]:
                    ev.emit("a0003", "think", text=eturn["think"])
                # 1. triage gate (cheap, before promotion)
                tp = is_true_positive(router, cand)
                ev.emit("a0003", "decision", kind="triage.true_positive",
                        outcome="true_positive" if tp else "false_positive")
                if not tp:
                    kb.add_rejection(cand, "triage", "likely false positive")
                    stage_counts["triage"] += 1
                    exploit.log(seq, "triage", cand.title,
                                "rejected — likely false positive", "rejected")
                    continue
                # 2-5. shared promotion path
                outcome = promote_candidate(router, cand, kb.accepted,
                                            config.posterior_min)
                if outcome.finding is not None:
                    # 4. INTERPRET — the generative LLM writes why it matters.
                    if self._planner is not None:
                        from aegis.llm import explain_finding
                        rationale = explain_finding(
                            self._planner, cand.title, cand.evidence)
                        if rationale:
                            outcome.finding.rationale = rationale
                    kb.add_finding(outcome.finding)
                    key = ("validated_exploitable" if outcome.exploitable
                           else "validated_informational")
                    stage_counts[key] += 1
                    if outcome.finding.rationale:
                        ev.emit("a0003", "assistant",
                                text=outcome.finding.rationale)
                    ev.emit("a0003", "finding", id=cand.id, title=cand.title,
                            severity=outcome.finding.severity,
                            exploitable=outcome.exploitable)
                    ev.emit("a0003", "message", to="a0001",
                            text=f"Filed {cand.id}: {cand.title} "
                                 f"({outcome.finding.severity}).")
                    # DYNAMIC SPAWN — a confirmed exploitable finding earns a
                    # dedicated subagent to develop it. The graph grows at run
                    # time, Strix-style (create_agent + inter-agent messages).
                    if outcome.exploitable and len(self.graph) < 8:
                        aid = f"a{len(self.graph) + 1:04d}"
                        task = f"develop PoC for {cand.title}"
                        sub = AgentNode(aid, AgentRole.POST_EXPLOITATION, task,
                                        "a0001", AgentStatus.RUNNING)
                        self.graph.append(sub)
                        ev.emit("a0001", "message", to=aid,
                                text=f"Spin up and develop a PoC for {cand.id}.")
                        ev.emit(aid, "spawn", role="post_exploitation",
                                task=task, parent_id="a0001")
                        ev.emit(aid, "status", status="running")
                        sub.steps_spent += 1
                        pturn = self._turn("post_exploitation", task,
                                           f"developing a PoC for {cand.title}",
                                           ["draft the PoC", "skip"])
                        ev.emit(aid, "assistant", text=pturn["assistant"])
                        if pturn["think"]:
                            ev.emit(aid, "think", text=pturn["think"])
                        sub.log(seq, "poc", cand.title,
                                "drafted a proof-of-concept", "exploit")
                        ev.emit(aid, "message", to="a0001",
                                text=f"PoC drafted for {cand.id}.")
                        ev.emit(aid, "finish",
                                summary=f"PoC ready for {cand.id}")
                    exploit.log(seq, "promote", cand.title,
                                outcome.finding.rationale or
                                ("confirmed exploitable" if outcome.exploitable
                                 else "promoted — informational"),
                                "exploit" if outcome.exploitable else "found")
                else:
                    kb.rejected.append(outcome.rejection)
                    stage_counts[outcome.stage] += 1
                    exploit.log(seq, "triage", cand.title,
                                f"dropped at {outcome.stage}", "rejected")
            else:  # finish
                coordinator.log(seq, "finish", "run complete",
                                f"{len(kb.accepted)} finding(s) confirmed")
                ev.emit("a0001", "finish",
                        summary=f"{len(kb.accepted)} finding(s) confirmed")
                break

        for node in self.graph:
            node.status = AgentStatus.COMPLETED
            ev.emit(node.id, "status", status="completed")
        kb.rank()

        return EngineReport(
            name=self.name, kind=self.kind, available=True, ran=True,
            candidates=len(candidates), accepted=len(kb.accepted),
            rejected=len(kb.rejected), stage_counts=stage_counts,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            extra={"graph": [n.as_dict() for n in self.graph],
                   "steps_spent": budget.steps_spent,
                   "tool_runs": self._tool_runs,
                   "transcript": self._events.events,
                   "degraded": any(r["status"] not in ("ok",)
                                   for r in self._tool_runs)},
        )

    @staticmethod
    def _context(kb: KnowledgeBase, unprobed, pending) -> str:
        # A real instruction, not a terse machine string: a deterministic
        # backend takes the sensible option (0) regardless, but an LLM judge
        # needs to be told the goal or it finishes immediately.
        return (
            "You are the coordinator agent driving a defensive security test of "
            "an authorized target. Choose the next action. Keep probing every "
            "attack surface and triaging every pending lead; only choose "
            "'finish' once there are no surfaces left to probe and no leads "
            "pending. Current state: "
            f"{len(unprobed)} attack surface(s) not yet probed, "
            f"{len(pending)} lead(s) pending triage, "
            f"{len(kb.accepted)} finding(s) confirmed so far."
        )


__all__ = ["DynamicEngine", "SampleProbe", "AgentNode", "AgentRole",
           "AgentStatus", "StepBudget"]
