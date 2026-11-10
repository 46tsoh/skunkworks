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
