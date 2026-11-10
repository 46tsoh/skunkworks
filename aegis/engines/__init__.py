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


def default_orchestrator() -> Orchestrator:
    """An orchestrator with both standard engines registered (dynamic, static)."""
    return Orchestrator([DynamicEngine(), StaticEngine()])


__all__ = [
    "Engine", "EngineReport", "RunConfig", "RunResult", "Orchestrator",
    "PipelineEngine", "DynamicEngine", "StaticEngine", "default_orchestrator",
]
