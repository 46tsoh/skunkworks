"""Aegis orchestration core: one orchestrator, two pluggable engines."""

from aegis.engines.base import (
    Engine,
    EngineReport,
    Orchestrator,
    PipelineEngine,
    RunConfig,
    RunResult,
)
from aegis.engines.dynamic import DynamicEngine
from aegis.engines.static import StaticEngine


def default_orchestrator(registry=None) -> Orchestrator:
    """An orchestrator with both standard engines registered (dynamic, static).

    With a ``registry`` (a ``ToolRegistry``), both engines source their
    candidates from the available tools of their kind; otherwise they read the
    bundled sample-target candidate files.
    """
    return Orchestrator([
        DynamicEngine(registry=registry),
        StaticEngine(registry=registry),
    ])


__all__ = [
    "Engine", "EngineReport", "RunConfig", "RunResult", "Orchestrator",
    "PipelineEngine", "DynamicEngine", "StaticEngine", "default_orchestrator",
]
