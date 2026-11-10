# Orchestrator — spec

## Purpose

The Orchestrator is the Aegis M2 component that drives the two pluggable
analysis engines (a Strix-style dynamic engine and a RAPTOR-style static engine)
over a single target and folds their results into one unified, deduplicated,
ranked report. It owns the one shared `aegis.decision.DecisionRouter` and the one
shared `aegis.knowledge.KnowledgeBase` that both engines use, so cross-engine
dedup and ranking happen once, centrally, rather than being two reports stapled
together. It is engine-agnostic: it knows only the `Engine` protocol, never an
engine's internals.

## Responsibilities / non-responsibilities

Responsibilities:
- Hold a registry of `Engine` instances and let callers select all of them or a
  named subset for a run.
- Build exactly one shared `DecisionRouter` for a run (from `AegisConfig`), and
  pass it, with one shared `KnowledgeBase`, to every engine.
- Run the selected engines over the target (in parallel by default, serially on
  request), collecting each engine's contribution.
- Merge all contributions into one `KnowledgeBase`, run the cross-engine dedup
  pass using the existing `dedupe.same_vuln` decision, and produce the final
  ranked ordering.
- Assemble a `RunResult` that records per-engine outcomes, run-level metrics,
  timing, the backend used, and the decision-log location; optionally persist a
  local run directory (`report.json` + `decisions.jsonl`).

Non-responsibilities:
- It does not implement engine logic (the agent graph, the hypothesis queue, any
  tool execution). Those live in `DynamicEngine` / `StaticEngine` (separate M2
  specs) and behind the M3 tool interface.
- It does not define `Candidate` / `Finding` / `Rejection` / `KnowledgeBase` /
  `DecisionRouter` — it reuses the M1 types unchanged.
- It does not score, triage, validate, or compute CVSS itself; the per-candidate
  analysis stages remain in `aegis.analysis.pipeline`, which each engine calls.
- It does not reach the network. Backend egress policy is enforced by
  `AegisConfig` (`local_only`), not re-implemented here.

## Data model

Reused M1 types (by name, unchanged): `aegis.knowledge.models.Candidate`,
`aegis.knowledge.models.Finding`, `aegis.knowledge.models.Rejection`,
`aegis.knowledge.base.KnowledgeBase`, `aegis.decision.DecisionRouter`,
`aegis.config.AegisConfig`.

```python
from typing import Optional, Protocol, Sequence, runtime_checkable

@runtime_checkable
class Engine(Protocol):
    """A pluggable analysis engine driven by the Orchestrator."""
    name: str          # unique registry key, e.g. "dynamic" / "static"
    kind: str          # "dynamic" | "static" (matches Candidate.source_engine usage)

    def available(self) -> bool: ...
    def enumerate_candidates(
        self, target: str, config: AegisConfig
    ) -> Sequence[Candidate]: ...
    def run(
        self,
        target: str,
        kb: KnowledgeBase,
        router: DecisionRouter,
        config: AegisConfig,
    ) -> "EngineReport": ...
```

```python
@dataclass
class EngineReport:
    """One engine's outcome within a run."""
    name: str
    kind: str
    available: bool
    ran: bool                      # False if skipped (unavailable / not selected)
    skipped_reason: Optional[str]  # set when ran is False
    candidates: int                # candidates the engine produced
    accepted: int                  # findings accepted into the engine's KB
    rejected: int                  # candidates the engine dropped
    stage_counts: dict             # the pipeline's per-stage drop counts
    duration_ms: float
    error: Optional[str] = None    # engine raised; run continues (fail-open)

    def as_dict(self) -> dict: ...
```

```python
@dataclass
class RunConfig:
    """Orchestrator-level run configuration (wraps AegisConfig)."""
    target: str                                 # local path or localhost URL only
    engines: Optional[Sequence[str]] = None     # None = all registered, in order
    aegis: AegisConfig = field(default_factory=AegisConfig)
    parallel: bool = True
    max_workers: Optional[int] = None           # default: len(selected engines)
    out_dir: Optional[Path] = None              # write report.json + decisions.jsonl
```

```python
@dataclass
class RunResult:
    """The unified outcome of one orchestrated run."""
    run_id: str                    # timestamp-based, local, deterministic-in-tests
    target: str
    backend: str                   # config.aegis.backend
    kb: KnowledgeBase              # the merged, deduped, ranked shared base
    engine_reports: list           # list[EngineReport], registry order
    cross_engine_dedup: int        # findings collapsed across engines
    started_at: float
    finished_at: float
    duration_ms: float
    decision_log_path: Optional[Path]
    report_path: Optional[Path]    # out_dir/report.json when persisted

    def as_dict(self) -> dict:
        """Unified report payload: kb.as_dict() plus a `run` block with
        engine_reports, cross_engine_dedup, timing, backend, run_id."""
```

## Interfaces

```python
class Orchestrator:
    def __init__(self, engines: Optional[Sequence[Engine]] = None) -> None:
        """Create an orchestrator, optionally pre-registering engines (order
        preserved)."""

    def register(self, engine: Engine) -> None:
        """Register an engine under `engine.name`. Re-registering a name raises
        ValueError; registration order is the run/report order."""

    def engine_names(self) -> list[str]:
        """Registered engine names in registration order."""

    def select(self, names: Optional[Sequence[str]]) -> list[Engine]:
        """Resolve `names` (None = all) to registered Engine instances, in
        registration order. An unknown name raises KeyError."""

    def run(
        self,
        config: RunConfig,
        router: Optional[DecisionRouter] = None,
    ) -> RunResult:
        """Drive the selected engines over `config.target` and return the unified
        `RunResult`. Builds one shared DecisionRouter (unless `router` is given,
        for tests/reuse) and one shared KnowledgeBase; merges, cross-dedups, and
        ranks. Engines are run in parallel when `config.parallel`. An engine that
        raises is recorded in its EngineReport (`error`) and the run continues."""
```

Reused helpers (not redefined): `aegis.analysis.backends.build_router(candidates,
config=...)` to construct the shared router (seeding the offline `HintBackend`),
`aegis.analysis.pipeline.run(router, candidates, posterior_min, kb=...)` which
each engine's `run` calls, `aegis.analysis.dedupe.find_duplicate(router, cand,
accepted)` for the cross-engine dedup pass, and `KnowledgeBase.merge` /
`KnowledgeBase.rank`.

A reference base implementation `PipelineEngine` (abstract) is expected: its
`run` does `cands = self.enumerate_candidates(target, config)` then
`aegis.analysis.pipeline.run(router, cands, config.posterior_min, kb=kb)` and
builds the `EngineReport` from the resulting `kb.metrics`. `DynamicEngine` and
`StaticEngine` subclass it and supply only `enumerate_candidates` (and, in M3,
their tool-driven production). This keeps every engine on the one decision-driven
pipeline.

## Algorithm / control flow

`Orchestrator.run(config, router=None)`:

1. **Select.** `engines = self.select(config.engines)`. Partition into runnable
   (`engine.available()` is True) and skipped; a skipped engine gets an
   `EngineReport(ran=False, skipped_reason=...)` and does not run.
2. **Seed the shared router** (offline determinism). If `router` was not passed,
   call `enumerate_candidates(target, config.aegis)` on every runnable engine and
   union the results into `all_candidates`. Build **one** router:
   `router = build_router(all_candidates, config=config.aegis)`. This seeds the
   `HintBackend` with the full cross-engine candidate set so the static backend
   can resolve every triage/dedup/validate/hypothesis decision deterministically.
   For `basal`/`jev` backends the real backend ignores the seed; the seeded
   `HintBackend` remains the fallback. The router is created once and shared by
   all engines — it is the single choke point, so every decision across both
   engines lands in one JSONL log, one cache, and one `RouterMetrics`.
   `enumerate_candidates` must be deterministic so the seed pass and the in-`run`
   production agree.
3. **Run engines.** Create one **private** `engine_kb = KnowledgeBase()` per
   runnable engine (so engines never mutate a shared list concurrently). Call
   `engine.run(target, engine_kb, router, config.aegis)`. When `config.parallel`,
   dispatch with a `ThreadPoolExecutor(max_workers)`; the shared `DecisionRouter`
   is already thread-safe (internal lock around cache + log + metrics), so
   concurrent engines calling `router.gate/score/choose` is safe, and the private
   KBs avoid any shared mutation. An engine that raises is caught: its report
   records `error`, its `engine_kb` is treated as empty, and the run proceeds
   (fail-open, mirroring the pipeline's resilience posture).
4. **Merge.** Create the master `kb = KnowledgeBase()`. For each engine (registry
   order), `kb.merge(engine_kb)`, folding accepted findings and rejections in.
   Intra-engine dedup already happened inside each engine's pipeline run (its
   stage-3 `dedupe` against its own accepted list).
5. **Cross-engine dedup** (the asked reconciliation). Sort the merged
   `kb.accepted` by the KB rank order (exploitable, then CVSS, then posterior) so
   the strongest representative is seen first. Walk the sorted list building a
   `kept` list of `Finding`s; for each finding `f`, call
   `find_duplicate(router, f.candidate, kept)` — the exact `dedupe.same_vuln`
   gate the single-engine pipeline uses. If it returns a duplicate, record
   `kb.add_rejection(f.candidate, "dedupe.cross_engine", f"duplicate of {dup.id}
   ({dup.title})")` and increment `cross_engine_dedup`; otherwise append `f` to
   `kept`. Replace `kb.accepted` with `kept`. Because the list was pre-sorted by
   strength, the retained finding is always the stronger of a pair, and the
   collapse reason references the kept finding for the audit trail.
6. **Rank.** `kb.rank()` to produce the final deterministic ordering.
7. **Metrics.** Set `kb.metrics` to a run-level aggregate: total candidates,
   accepted, rejected, `cross_engine_dedup`, per-engine accepted/rejected,
   `decisions`/`decision_cache_hits`/`decisions_by_backend` read from
   `router.metrics`, and the per-engine `stage_counts`.
8. **Assemble & persist.** Build the `RunResult` (run_id, timing, backend,
   engine_reports, decision_log_path). If `config.out_dir` is set, write
   `report.json` (`RunResult.as_dict()`) and the router's `decisions.jsonl`
   there; both are local files.

```
select → seed one router → run engines (parallel, private KBs)
       → merge into one KB → cross-engine dedup (dedupe.same_vuln) → rank → RunResult
```

## Testability

- **Offline + deterministic.** With `AegisConfig(backend="static")`, the shared
  router uses the `HintBackend`, which resolves every decision from each
  candidate's `hints` via the `[ref=...]` tag. No model server, no network. Given
  fixed sample candidates, a run is fully reproducible: same accepted set, same
  ranking, same `cross_engine_dedup` count.
- **Cross-engine dedup is driven by data, not luck.** A sample candidate produced
  by one engine carries `hints["duplicate_of"] = "<id of the other engine's
  candidate>"`; the `HintBackend` returns ~0.96 for that pair's `dedupe.same_vuln`
  gate and ~0.03 otherwise, so the collapse is assertable (`cross_engine_dedup ==
  N`, specific id moved to `rejected` with stage `dedupe.cross_engine`).
- **Determinism of parallel runs.** Private per-engine KBs plus a thread-safe
  router mean `parallel=True` and `parallel=False` yield the same final KB; a test
  can assert equality across both modes. `run_id` is injectable/overridable so
  golden-file comparison of `report.json` is stable.
- **Fake engines.** Tests register trivial `Engine` stubs (a `name`, a `kind`, an
  `available()`, an `enumerate_candidates` returning fixtures, and a `run`
  delegating to `pipeline.run`) to exercise selection, skipping of unavailable
  engines, fail-open on a raising engine, and merge/dedup — without the real
  dynamic/static engines.
- **Seam coverage.** Because all decisions flow through the one router, a test can
  point `log_path` at a temp file and assert the decision trail (kinds `triage.*`,
  `hypothesis.*`, `dedupe.same_vuln`, `validate.stage`) is complete and ordered.

## Local-only notes

- The target is a local filesystem path (the bundled sample) or a localhost URL;
  the orchestrator never dials out. Any remote backend is already refused by
  `AegisConfig` when `local_only` is set (the default), which raises for `jev`.
- Parallelism is **in-process threads**, not distributed workers, container pools,
  or a remote scheduler. This is the deliberate local-only analogue of Strix's
  container-per-agent runtime and RAPTOR's model-dispatch broker: same
  "many units, one shared store" shape, zero infrastructure.
- All outputs (`report.json`, `decisions.jsonl`, the run directory) are written to
  the local filesystem under `config.out_dir`; nothing is uploaded or hosted. The
  M5 UI reads these local files (and, later, a local run stream).

## Open questions / deferred

- **Double enumeration.** `enumerate_candidates` is called once to seed the router
  and again inside each engine's `run`. It is deterministic and cheap offline, so
  this is acceptable; a later refactor could let `run` accept the already-produced
  candidates to call it once. Deferred.
- **Dedup merge vs drop.** The cross-engine pass currently drops the weaker
  duplicate. Merging the two findings' evidence/provenance (so a finding shows it
  was confirmed by both engines) is a richer behavior deferred to a later pass.
- **Budgets / cost caps.** Strix's budget policy (stop/pause) and RAPTOR's per-run
  cost caps are not modeled here; the M2 orchestrator runs engines to completion.
  A per-engine budget hook is deferred to a later milestone.
- **Resume / checkpointing.** Strix snapshots agent state and RAPTOR tracks a
  resumable run directory; Aegis M2 runs are single-shot. Resume is deferred.
- **Live streaming.** Emitting an incremental event stream for the M5 live-run
  view (decisions ticking through the router) is deferred; M2 returns a final
  `RunResult`.
- **Inter-engine signalling.** Strix agents message each other mid-run. M2 engines
  share only the KB + router and do not exchange messages; a shared-blackboard
  hand-off between engines is deferred.

## Upstream patterns credited (for NOTICE)

- **Strix — `AgentCoordinator` single-owner registry of parallel units over one
  shared findings store** (`strix/core/agents.py`): drawn on for the Orchestrator
  as the single owner of an engine registry whose units run in parallel and write
  into one shared `KnowledgeBase`, with per-unit lifecycle/outcome records.
- **Strix — graph-of-agents parallel execution with a shared blackboard**
  (`strix/tools/agents_graph/`, `strix/runtime/`): drawn on for running multiple
  engines concurrently against one target while sharing the router + KB, realized
  locally as in-process threads instead of container-per-agent runtimes.
- **Strix — LLM deduplication of findings (same underlying vulnerability)**: the
  shape behind the `dedupe.same_vuln` decision reused here for the cross-engine
  reconciliation pass (via `aegis.analysis.dedupe`).
- **RAPTOR — tracked run lifecycle and run-directory outcome record**
  (`raptor/core/run/`, `raptor/bin/raptor`): drawn on for the `RunResult` object,
  the run id/timing/backend metadata, and the optional local run directory holding
  `report.json` + `decisions.jsonl`.
- **RAPTOR — orchestration result funnel / enrichment-pass bucketing**
  (`raptor/core/orchestration/funnel.py`, `agentic_passes.py`): drawn on for the
  per-engine `EngineReport` and the run-level aggregate metrics that bucket each
  engine's candidate/accept/reject/stage counts into one summary.
- **RAPTOR — unified dispatch broker with a single decision log**
  (`raptor/core/dispatch/`): drawn on for routing every engine's decisions through
  one shared, observable `DecisionRouter` choke point rather than per-engine model
  calls.
- **RAPTOR — generate-and-verify `Proposer` / `Oracle` Protocol seam**
  (`raptor/core/orchestration/driver.py`): drawn on for expressing the engine
  boundary as a small `typing.Protocol` (`Engine`) with a uniform `run(...)`
  contract, so engines are pluggable and the orchestrator stays engine-agnostic.
```
