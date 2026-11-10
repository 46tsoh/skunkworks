"""Integration: the tool registry feeding the engines and orchestrator (offline)."""

from aegis.config import AegisConfig
from aegis.engines import StaticEngine, default_orchestrator
from aegis.engines.base import RunConfig
from aegis.knowledge.base import KnowledgeBase
from aegis.analysis.backends import build_router
from aegis.tools import default_registry
from aegis.tools.base import ToolKind


def test_registry_runs_all_adapters_offline():
    reg = default_registry(prefer_docker=False)
    assert len(reg.names()) == 17
    for name in reg.names():
        result = reg.run(name, "data/sample_target")
        assert result.ok, f"{name} not OK"
        assert result.candidates, f"{name} produced no candidates"


def test_static_engine_sources_from_registry():
    reg = default_registry(prefer_docker=False)
    engine = StaticEngine(registry=reg)
    cands = list(engine.enumerate_candidates("data/sample_target", AegisConfig()))
    # Every static tool contributes; all stamped as the static engine's kind.
    assert cands and all(c.source_engine == "static" for c in cands)
    tools = {c.metadata.get("tool") for c in cands}
    assert {"semgrep", "sca", "codeql"} <= tools


def test_orchestrator_with_registry_merges_both_engines():
    reg = default_registry(prefer_docker=False)
    result = default_orchestrator(registry=reg).run(
        RunConfig(target="data/sample_target", parallel=False, run_id="tools"))
    # Dynamic tools + static tools both contribute to the unified KB.
    engines = result.kb.engine_counts()
    assert engines.get("dynamic", 0) > 0 and engines.get("static", 0) > 0
    assert result.kb.accepted  # findings flowed tool -> engine -> pipeline -> KB


def test_failing_tool_marks_run_degraded_not_clean():
    # A tool that errors must be reported, never silently dropped (no fail-open).
    from aegis.tools.base import Tool, ToolKind, ToolResult, ToolStatus, ToolRegistry
    from aegis.engines import DynamicEngine, StaticEngine, Orchestrator

    class FailingTool:
        name = "boomtool"
        kind = ToolKind.STATIC
        requires_binary = None
        def available(self):
            return True
        def run(self, target, **opts):
            return ToolResult("boomtool", ToolStatus.ERROR, errors=["kaboom"],
                              target=target)

    reg = ToolRegistry()
    reg.register(FailingTool())
    result = Orchestrator([StaticEngine(registry=reg)]).run(
        RunConfig(target="data/sample_target", parallel=False, run_id="deg"))
    assert result.kb.metrics["degraded"] is True
    failures = result.kb.metrics["tool_failures"]
    assert any(f["name"] == "boomtool" and f["status"] == "error" for f in failures)


def test_clean_run_is_not_degraded():
    reg = default_registry(prefer_docker=False)
    result = default_orchestrator(registry=reg).run(
        RunConfig(target="data/sample_target", parallel=False, run_id="clean"))
    assert result.kb.metrics["degraded"] is False
    assert result.kb.metrics["tool_failures"] == []


def test_tool_candidates_run_through_pipeline():
    from aegis.analysis.pipeline import run
    reg = default_registry(prefer_docker=False)
    cands = [c for t in reg.by_kind(ToolKind.STATIC)
             for c in t.run("data/sample_target").candidates]
    router = build_router(cands, config=AegisConfig())
    kb = run(router, cands)
    assert kb.metrics["candidates"] == len(cands)
    assert kb.accepted
