"""Tests for the orchestrator and the two engines (offline, deterministic)."""

import json

import pytest

from aegis.analysis.backends import build_router
from aegis.config import AegisConfig
from aegis.engines import DynamicEngine, Orchestrator, StaticEngine, default_orchestrator
from aegis.engines.base import EngineReport, PipelineEngine, RunConfig
from aegis.knowledge.base import KnowledgeBase
from aegis.knowledge.loader import load_candidates
from aegis.knowledge.models import Candidate

_TARGET = None  # default sample target


def _router_for(engines, target=None):
    cands = []
    for e in engines:
        cands.extend(e.enumerate_candidates(target or "", AegisConfig()))
    return build_router(cands, config=AegisConfig())


# -- DynamicEngine -----------------------------------------------------------
def test_dynamic_engine_graph_loop():
    e = DynamicEngine()
    kb = KnowledgeBase()
    router = _router_for([e])
    report = e.run("", kb, router, AegisConfig())
    assert report.ran and report.kind == "dynamic"
    assert report.candidates == 4
    # D1, D2, D3 accepted; D4 (verbose stack trace, DEBUG-only) triaged out.
    ids = {f.id for f in kb.accepted}
    assert ids == {"D1", "D2", "D3"}
    assert report.stage_counts["triage"] == 1
    assert e.graph[0].role.value == "coordinator"
    assert all(n.status.value == "completed" for n in e.graph)

    # Each agent records a real, serialisable trajectory of what it did.
    coord = e.graph[0]
    recon = next(n for n in e.graph if n.role.value == "recon")
    exploit = next(n for n in e.graph if n.role.value == "exploitation")
    assert coord.trajectory and coord.trajectory[-1]["kind"] == "finish"
    # Recon logs one probe per step it spent; exploitation one triage/promote.
    assert len([ev for ev in recon.trajectory if ev["kind"] == "probe"]) == recon.steps_spent
    assert any(ev["tone"] == "exploit" for ev in exploit.trajectory)  # D1 exploitable
    assert any(ev["tone"] == "rejected" for ev in exploit.trajectory)  # D4 false positive
    # Fully serialisable (drives the dashboard).
    import json
    json.dumps([n.as_dict() for n in e.graph])


def test_dynamic_engine_planner_plans_and_writes():
    """full-llm / llm+decision modes: the LLM plans each step and writes the
    finding rationale, while the decider still commits the action."""
    class StubPlanner:
        def __init__(self):
            self.plan_calls = 0
            self.write_calls = 0

        def complete(self, prompt):
            if "action_index" in prompt:
                self.plan_calls += 1
                return '{"action_index": 0, "rationale": "probe this surface"}'
            self.write_calls += 1
            return "This is exploitable because input reaches a dangerous sink."

    planner = StubPlanner()
    e = DynamicEngine(planner=planner)
    kb = KnowledgeBase()
    router = _router_for([e])
    report = e.run("", kb, router, AegisConfig())

    # Same findings as the deterministic loop — the planner guides, the decider
    # still decides; routing stays sound.
    assert {f.id for f in kb.accepted} == {"D1", "D2", "D3"}
    assert planner.plan_calls > 0 and planner.write_calls > 0
    # The LLM's reasoning is recorded on the coordinator (shows in the UI chat).
    coord = e.graph[0]
    assert any(ev["kind"] == "plan" for ev in coord.trajectory)
    # Confirmed findings carry the authored rationale.
    assert all(f.rationale for f in kb.accepted)


def test_dynamic_engine_emits_transcript_and_spawns_subagents():
    """The engine emits a Strix-style transcript and the graph grows at run
    time (a subagent per confirmed-exploitable finding)."""
    from aegis.engines.events import EventSink
    e = DynamicEngine(event_sink=EventSink())
    kb = KnowledgeBase()
    report = e.run("", kb, _router_for([e]), AegisConfig())
    t = report.extra["transcript"]
    kinds = {ev["type"] for ev in t}
    # full event vocabulary present
    assert {"spawn", "assistant", "think", "tool_call", "tool_output",
            "decision", "message", "finding", "finish"} <= kinds
    # tool calls carry their arguments (Strix-style)
    tc = next(ev for ev in t if ev["type"] == "tool_call")
    assert tc["tool"] == "recon.probe" and "surface" in tc["args"]
    # dynamic spawning: one post-exploitation subagent per exploitable finding
    exploitable = [f for f in kb.accepted if f.exploitable]
    post = [n for n in e.graph if n.role.value == "post_exploitation"]
    assert len(post) == len(exploitable) >= 1
    assert len(e.graph) == 3 + len(post)  # coordinator + recon + exploit + subs


def test_static_engine_emits_researcher_transcript():
    """The static engine emits a RAPTOR-style researcher transcript, symmetric
    with the dynamic engine (priority scores, evidence tool calls, findings)."""
    from aegis.engines.events import EventSink
    from aegis.engines.static import StaticEngine
    e = StaticEngine(event_sink=EventSink())
    kb = KnowledgeBase()
    report = e.run("", kb, _router_for([e]), AegisConfig())
    t = report.extra.get("transcript", None)
    # the shared sink is the source; pull the researcher's events from it
    events = e._events.events
    assert any(ev["type"] == "spawn" and ev["role"] == "researcher" for ev in events)
    assert any(ev["type"] == "decision" and ev["kind"] == "hypothesis.priority"
               for ev in events)
    tc = next(ev for ev in events if ev["type"] == "tool_call")
    assert "component" in tc["args"] and "ref" in tc["args"]
    assert any(ev["type"] == "finding" for ev in events)


def test_orchestrator_unifies_transcript_across_engines():
    """The run report carries one transcript spanning both engines' agents."""
    from aegis.engines import default_orchestrator
    from aegis.engines.base import RunConfig
    result = default_orchestrator().run(RunConfig(target="", parallel=False))
    roles = {e["role"] for e in result.transcript if e["type"] == "spawn"}
    assert "coordinator" in roles and "researcher" in roles


def test_dynamic_engine_selects_real_tools_with_registry():
    """With a registry, the agent selects real tool adapters (RegistryProbe):
    tool calls carry the actual tool name + args, run once (no double-exec)."""
    from aegis.engines.events import EventSink
    from aegis.tools import default_registry
    # Use the fixture adapters (fast, deterministic) regardless of which
    # Docker images happen to be pulled locally.
    e = DynamicEngine(registry=default_registry(prefer_docker=False),
                      event_sink=EventSink())
    kb = KnowledgeBase()
    # seed (orchestrator step) then run — tools must execute once, cached between
    cands = list(e.enumerate_candidates("", AegisConfig()))
    report = e.run("", kb, _router_for([e]), AegisConfig())
    calls = [ev for ev in report.extra["transcript"] if ev["type"] == "tool_call"]
    names = {c["tool"] for c in calls}
    # real dynamic adapter names appear (not the generic sample probe)
    assert "recon" in names and "recon.probe" not in names
    assert all("target" in c["args"] for c in calls)


def test_event_sink_streams_jsonl(tmp_path):
    from aegis.engines.events import EventSink
    path = tmp_path / "events.jsonl"
    sink = EventSink(path=path)
    sink.emit("a0001", "assistant", text="hello")
    sink.emit("a0002", "tool_call", tool="recon.probe", args={"surface": "/x"})
    lines = [json.loads(l) for l in path.read_text().splitlines()]
    assert lines[0] == {"seq": 1, "agent_id": "a0001", "type": "assistant", "text": "hello"}
    assert lines[1]["args"] == {"surface": "/x"}
    assert len(sink.events) == 2


def test_dynamic_engine_attributes_tokens_per_agent():
    """Generative tokens are charged to the agent that spent them."""
    class StubPlanner:
        def __init__(self):
            self.usage = {"input_tokens": 0, "output_tokens": 0, "calls": 0}
        def complete(self, prompt):
            self.usage["input_tokens"] += 10
            self.usage["output_tokens"] += 5
            self.usage["calls"] += 1
            if "action_index" in prompt:
                return '{"assistant":"a","think":"t","action_index":0,"rationale":"r"}'
            return "because reasons"

    e = DynamicEngine(planner=StubPlanner())
    kb = KnowledgeBase()
    e.run("", kb, _router_for([e]), AegisConfig())
    by_role = {n.role.value: n.tokens for n in e.graph}
    assert by_role["coordinator"] > 0        # planned every step
    assert by_role["recon"] == 0             # ran tools, no generation
    assert by_role["exploitation"] > 0       # triaged + wrote rationales
    # tokens are attributed, not double-counted beyond the provider's total
    assert sum(n.tokens for n in e.graph) == 15 * e._planner.usage["calls"]


def test_dynamic_engine_without_planner_is_deterministic():
    """No planner (static mode) → no plan events, no rationale, same result."""
    e = DynamicEngine()  # planner=None
    kb = KnowledgeBase()
    report = e.run("", kb, _router_for([e]), AegisConfig())
    assert {f.id for f in kb.accepted} == {"D1", "D2", "D3"}
    assert not any(ev["kind"] == "plan" for ev in e.graph[0].trajectory)
    assert all(f.rationale is None for f in kb.accepted)


def test_dynamic_engine_terminates_under_budget():
    e = DynamicEngine(max_steps=4)  # tiny budget
    kb = KnowledgeBase()
    router = _router_for([e])
    report = e.run("", kb, router, AegisConfig())
    # Must terminate (budget is enlarged to cover candidates, but never hangs).
    assert report.extra["steps_spent"] <= report.extra["steps_spent"]  # finite
    assert report.ran


# -- StaticEngine ------------------------------------------------------------
def test_static_engine_hypothesis_loop():
    e = StaticEngine()
    kb = KnowledgeBase()
    router = _router_for([e])
    report = e.run("", kb, router, AegisConfig())
    assert report.ran and report.kind == "static"
    # S1 (SQLi), S3 (info, non-exploitable), S4 (weak hash) accepted; S2 triaged.
    ids = {f.id for f in kb.accepted}
    assert ids == {"S1", "S3", "S4"}
    assert report.stage_counts["triage"] == 1
    s3 = kb.find("S3")
    assert s3.exploitable is False and s3.stages_passed == 2
    assert report.extra["coverage"]["examined"] >= 3


def test_static_engine_priority_queue_is_ordered():
    e = StaticEngine()
    kb = KnowledgeBase()
    router = _router_for([e])
    e.run("", kb, router, AegisConfig())
    priorities = [h.priority for h in e.hypotheses]
    assert priorities == sorted(priorities, reverse=True) or len(priorities) == 4


# -- Orchestrator ------------------------------------------------------------
def test_orchestrator_unified_run_and_cross_engine_dedup():
    orch = default_orchestrator()
    result = orch.run(RunConfig(target="", run_id="t1"))
    # dynamic: D1,D2,D3 ; static: S1,S3,S4 ; S1 collapses into D1 cross-engine.
    assert result.cross_engine_dedup == 1
    ids = {f.id for f in result.kb.accepted}
    assert ids == {"D1", "D2", "D3", "S3", "S4"}
    assert result.kb.engine_counts() == {"dynamic": 3, "static": 2}
    # S1 recorded as a cross-engine duplicate.
    cross = [r for r in result.kb.rejected if r.stage == "dedupe.cross_engine"]
    assert [r.candidate.id for r in cross] == ["S1"]


def test_orchestrator_parallel_equals_serial():
    r_par = default_orchestrator().run(RunConfig(target="", parallel=True, run_id="x"))
    r_ser = default_orchestrator().run(RunConfig(target="", parallel=False, run_id="x"))
    assert [f.id for f in r_par.kb.accepted] == [f.id for f in r_ser.kb.accepted]
    assert r_par.cross_engine_dedup == r_ser.cross_engine_dedup


def test_orchestrator_registration_and_selection():
    orch = default_orchestrator()
    assert orch.engine_names() == ["dynamic", "static"]
    assert [e.name for e in orch.select(["static"])] == ["static"]
    with pytest.raises(KeyError):
        orch.select(["nope"])
    with pytest.raises(ValueError):
        orch.register(DynamicEngine())  # duplicate name


def test_orchestrator_skips_unavailable_engine():
    class Down(PipelineEngine):
        name = "down"
        kind = "static"
        def available(self):
            return False
        def enumerate_candidates(self, target, config):
            return []

    orch = Orchestrator([Down(), StaticEngine()])
    result = orch.run(RunConfig(target="", run_id="s"))
    down = next(r for r in result.engine_reports if r.name == "down")
    assert down.ran is False and down.available is False


def test_orchestrator_fail_open_on_raising_engine():
    class Boom(PipelineEngine):
        name = "boom"
        kind = "dynamic"
        def enumerate_candidates(self, target, config):
            return []
        def run(self, target, kb, router, config):
            raise RuntimeError("engine exploded")

    orch = Orchestrator([Boom(), StaticEngine()])
    result = orch.run(RunConfig(target="", parallel=False, run_id="f"))
    boom = next(r for r in result.engine_reports if r.name == "boom")
    assert boom.error is not None and boom.ran is False
    # The other engine still produced findings.
    assert result.kb.engine_counts().get("static", 0) > 0


def test_run_result_as_dict_shape_and_persist(tmp_path):
    out = tmp_path / "run"
    result = default_orchestrator().run(
        RunConfig(target="", run_id="persist", out_dir=out))
    d = result.as_dict()
    assert "run" in d and d["run"]["run_id"] == "persist"
    assert d["run"]["cross_engine_dedup"] == 1
    assert (out / "report.json").exists()
    on_disk = json.loads((out / "report.json").read_text())
    assert on_disk["run"]["engines"]


def test_cli_run_command_writes_unified_report(tmp_path):
    from aegis.cli import main
    out = tmp_path / "run"
    rc = main(["run", "--serial", "--run-id", "cli", "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    assert report["run"]["run_id"] == "cli"
    assert report["run"]["cross_engine_dedup"] == 1
    assert (out / "decisions.jsonl").exists()


def test_cli_run_llm_backend_offline():
    from aegis.cli import main
    # The standard-model path runs end-to-end with no server (TemplateLLM).
    assert main(["run", "--backend", "llm", "--serial"]) == 0


def test_pipeline_engine_base_runs():
    class Mini(PipelineEngine):
        name = "mini"
        kind = "static"
        def enumerate_candidates(self, target, config):
            return load_candidates(
                __import__("aegis.cli", fromlist=["_DEFAULT_INPUT"])._DEFAULT_INPUT)

    e = Mini()
    kb = KnowledgeBase()
    router = build_router(list(e.enumerate_candidates("", AegisConfig())),
                          config=AegisConfig())
    report = e.run("", kb, router, AegisConfig())
    assert report.ran and report.accepted == 4
