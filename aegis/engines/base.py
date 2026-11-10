"""Orchestration core: one orchestrator driving two pluggable engines.

See `docs/specs/orchestrator.md`. The Orchestrator owns one shared
:class:`DecisionRouter` and one shared :class:`KnowledgeBase`, runs the selected
engines over a target (each into a private KB), merges them, runs a cross-engine
dedup pass through the same ``dedupe.same_vuln`` decision, ranks, and returns a
unified :class:`RunResult`. Everything is local-only and offline-deterministic
with the ``static`` backend.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, Sequence, runtime_checkable

from aegis.analysis.backends import build_router
from aegis.analysis.dedupe import find_duplicate
from aegis.config import AegisConfig
from aegis.decision import DecisionRouter
from aegis.knowledge.base import KnowledgeBase
from aegis.knowledge.models import Candidate


@runtime_checkable
class Engine(Protocol):
    """A pluggable analysis engine driven by the Orchestrator."""

    name: str
    kind: str

    def available(self) -> bool: ...
    def enumerate_candidates(
        self, target: str, config: AegisConfig
    ) -> Sequence[Candidate]: ...
    def run(
        self, target: str, kb: KnowledgeBase, router: DecisionRouter,
        config: AegisConfig,
    ) -> "EngineReport": ...


@dataclass
class EngineReport:
    """One engine's outcome within a run."""

    name: str
    kind: str
    available: bool
    ran: bool
    skipped_reason: Optional[str] = None
    candidates: int = 0
    accepted: int = 0
    rejected: int = 0
    stage_counts: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)  # engine-specific snapshot (graph/coverage/...)

    def as_dict(self) -> dict:
        return {
            "name": self.name, "kind": self.kind, "available": self.available,
            "ran": self.ran, "skipped_reason": self.skipped_reason,
            "candidates": self.candidates, "accepted": self.accepted,
            "rejected": self.rejected, "stage_counts": self.stage_counts,
            "duration_ms": round(self.duration_ms, 2), "error": self.error,
            "extra": self.extra,
        }


@dataclass
class RunConfig:
    """Orchestrator-level run configuration (wraps AegisConfig)."""

    target: str
    engines: Optional[Sequence[str]] = None
    aegis: AegisConfig = field(default_factory=AegisConfig)
    parallel: bool = True
    max_workers: Optional[int] = None
    out_dir: Optional[Path] = None
    run_id: Optional[str] = None  # injectable for deterministic tests


@dataclass
class RunResult:
    """The unified outcome of one orchestrated run."""

    run_id: str
    target: str
    backend: str
    kb: KnowledgeBase
    engine_reports: list
    cross_engine_dedup: int
    started_at: float
    finished_at: float
    duration_ms: float
    decision_log_path: Optional[Path] = None
    report_path: Optional[Path] = None

    def as_dict(self) -> dict:
        payload = self.kb.as_dict()
        payload["run"] = {
            "run_id": self.run_id,
            "target": self.target,
            "backend": self.backend,
            "engines": [r.as_dict() for r in self.engine_reports],
            "cross_engine_dedup": self.cross_engine_dedup,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": round(self.duration_ms, 2),
            "decision_log_path": (str(self.decision_log_path)
                                  if self.decision_log_path else None),
        }
        return payload


_RANK_KEY = lambda f: (f.exploitable, f.cvss_score, f.posterior)  # noqa: E731


def _candidates_from_tools(registry, kind_str: str, target: str,
                           tool_names=None):
    """Run the registry's available tools of a kind; collect candidates + status.

    Returns ``(candidates, tool_runs)`` where ``tool_runs`` is a per-tool record
    ``{name, status, errors, candidates}``. A tool that errors does NOT silently
    vanish: its failure is reported so the engine can mark the run degraded
    rather than present an incomplete scan as clean (never fail-open on
    integrity).
    """
    from aegis.tools.base import ToolKind
    kind = ToolKind(kind_str)
    if tool_names:
        tools = [registry.get(n) for n in tool_names
                 if registry.get(n).kind == kind and registry.get(n).available()]
    else:
        tools = registry.available(kind)
    out: list = []
    tool_runs: list = []
    for tool in tools:
        result = tool.run(target)
        tool_runs.append({"name": result.tool, "status": result.status.value,
                          "errors": list(result.errors),
                          "candidates": len(result.candidates)})
        if result.ok:
            for c in result.candidates:
                c.source_engine = kind_str
            out.extend(result.candidates)
    return out, tool_runs


class Orchestrator:
    """Drives registered engines over one target into one unified report."""

    def __init__(self, engines: Optional[Sequence[Engine]] = None) -> None:
        self._engines: dict = {}
        self._order: list = []
        for e in engines or []:
            self.register(e)

    def register(self, engine: Engine) -> None:
        if engine.name in self._engines:
            raise ValueError(f"engine {engine.name!r} already registered")
        self._engines[engine.name] = engine
        self._order.append(engine.name)

    def engine_names(self) -> list:
        return list(self._order)

    def select(self, names: Optional[Sequence[str]]) -> list:
        if names is None:
            return [self._engines[n] for n in self._order]
        out = []
        for n in names:
            if n not in self._engines:
                raise KeyError(f"unknown engine {n!r}")
            out.append(self._engines[n])
        return out

    def run(self, config: RunConfig,
            router: Optional[DecisionRouter] = None) -> RunResult:
        started = time.time()
        t0 = time.perf_counter()
        selected = self.select(config.engines)
        runnable = [e for e in selected if e.available()]
        skipped = [e for e in selected if not e.available()]

        # One shared router, seeded with the union of candidates for the
        # offline static backend to resolve every decision deterministically.
        if router is None:
            all_cands: list = []
            for e in runnable:
                all_cands.extend(e.enumerate_candidates(config.target, config.aegis))
            router = build_router(all_cands, config=config.aegis)

        reports: dict = {}
        engine_kbs: dict = {}

        def _run_one(engine):
            kb = KnowledgeBase()
            try:
                report = engine.run(config.target, kb, router, config.aegis)
            except Exception as exc:  # fail-open: record and continue
                report = EngineReport(
                    name=engine.name, kind=engine.kind, available=True,
                    ran=False, skipped_reason=None, error=repr(exc),
                )
            return engine.name, kb, report

        if runnable:
            if config.parallel and len(runnable) > 1:
                workers = config.max_workers or len(runnable)
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    for name, kb, rep in ex.map(_run_one, runnable):
                        engine_kbs[name] = kb
                        reports[name] = rep
            else:
                for engine in runnable:
                    name, kb, rep = _run_one(engine)
                    engine_kbs[name] = kb
                    reports[name] = rep

        for engine in skipped:
            reports[engine.name] = EngineReport(
                name=engine.name, kind=engine.kind, available=False,
                ran=False, skipped_reason="engine unavailable",
            )

        # Merge into the master KB in registry order.
        master = KnowledgeBase()
        for name in self._order:
            if name in engine_kbs:
                master.merge(engine_kbs[name])

        # Cross-engine dedup: strongest representative first, collapse the rest.
        master.accepted.sort(key=_RANK_KEY, reverse=True)
        kept: list = []
        cross_dedup = 0
        for f in master.accepted:
            dup = find_duplicate(router, f.candidate, kept)
            if dup is not None:
                master.add_rejection(
                    f.candidate, "dedupe.cross_engine",
                    f"duplicate of {dup.id} ({dup.title})")
                cross_dedup += 1
            else:
                kept.append(f)
        master.accepted = kept
        master.rank()

        ordered_reports = [reports[n] for n in self._order if n in reports]
        master.metrics = {
            "candidates": sum(r.candidates for r in ordered_reports),
            "accepted": len(master.accepted),
            "rejected": len(master.rejected),
            "cross_engine_dedup": cross_dedup,
            "engines": {r.name: {"accepted": r.accepted, "rejected": r.rejected}
                        for r in ordered_reports},
            "decisions": router.metrics.calls,
            "decision_cache_hits": router.metrics.cache_hits,
            "decisions_by_backend": dict(router.metrics.by_backend),
        }
        # Integrity: a scan is 'degraded' if any engine raised or any tool it
        # ran did not return OK — never present an incomplete scan as clean.
        tool_failures = []
        degraded = False
        for r in ordered_reports:
            if r.error:
                degraded = True
            for tr in r.extra.get("tool_runs", []):
                if tr["status"] != "ok":
                    tool_failures.append({"engine": r.name, **tr})
            if r.extra.get("degraded"):
                degraded = True
        master.metrics["degraded"] = degraded
        master.metrics["tool_failures"] = tool_failures

        finished = time.time()
        duration_ms = (time.perf_counter() - t0) * 1000.0
        run_id = config.run_id or f"run-{int(started)}"
        report_path = None
        decision_log_path = config.aegis.log_path

        result = RunResult(
            run_id=run_id, target=config.target, backend=config.aegis.backend,
            kb=master, engine_reports=ordered_reports,
            cross_engine_dedup=cross_dedup, started_at=started,
            finished_at=finished, duration_ms=duration_ms,
            decision_log_path=decision_log_path, report_path=report_path,
        )

        if config.out_dir:
            import json
            config.out_dir.mkdir(parents=True, exist_ok=True)
            report_path = config.out_dir / "report.json"
            report_path.write_text(json.dumps(result.as_dict(), indent=2),
                                   encoding="utf-8")
            result.report_path = report_path
        return result


class PipelineEngine:
    """Reference engine base: enumerate candidates, run the shared pipeline.

    Concrete engines subclass this and supply ``name``, ``kind``, and
    ``enumerate_candidates``. Engines that need a richer loop (the real dynamic
    and static engines) override ``run`` but keep the same protocol.
    """

    name = "pipeline"
    kind = "static"

    def available(self) -> bool:
        return True

    def enumerate_candidates(self, target: str,
                             config: AegisConfig) -> Sequence[Candidate]:
        raise NotImplementedError

    def run(self, target: str, kb: KnowledgeBase, router: DecisionRouter,
            config: AegisConfig) -> EngineReport:
        from aegis.analysis.pipeline import run as pipeline_run
        t0 = time.perf_counter()
        cands = list(self.enumerate_candidates(target, config))
        for c in cands:
            c.source_engine = self.kind
        pipeline_run(router, cands, posterior_min=config.posterior_min, kb=kb)
        m = kb.metrics
        return EngineReport(
            name=self.name, kind=self.kind, available=True, ran=True,
            candidates=len(cands), accepted=m["accepted"], rejected=m["rejected"],
            stage_counts=m["stage_counts"],
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )


__all__ = [
    "Engine", "EngineReport", "RunConfig", "RunResult", "Orchestrator",
    "PipelineEngine",
]
