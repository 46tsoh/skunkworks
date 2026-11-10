# DynamicEngine — spec

*Aegis M2. Strix-style graph-of-agents loop. Clean-room: written from a reading
of the upstream behavior, not its source.*

## Purpose

`DynamicEngine` is one of the two pluggable engines the M2 orchestrator drives
(the other is `StaticEngine`). It reproduces Strix's "graph of agents" shape as
a small, deterministic, offline loop: a set of specialist agent roles share one
blackboard, take bounded parallel steps against a single authorized/sample
target, and surface `Candidate`s. Every branch the loop takes — which role acts
next, whether a raw candidate is worth expensive work — is a typed decision
through `DecisionRouter`, and every accepted result becomes a `Finding` in the
one shared `KnowledgeBase`. It is tool-agnostic: real capabilities arrive in M3
behind a `Tool` interface, and until then the engine runs end-to-end on a
deterministic offline candidate source seeded from the bundled sample.

## Responsibilities / non-responsibilities

**Responsibilities**
- Own an agent graph: create roles, track parent/child and status, schedule steps.
- Own a shared `Blackboard` (observations, work claims, inter-agent messages, a
  coverage ledger) that all agents read and write.
- Drive the loop within a `StepBudget` (max steps / max agents) and terminate
  cleanly when the budget is spent, no agent is active, or the root finishes.
- Make the "what acts next" decision a routing call (`DecisionRouter.choose`).
- Triage each raw candidate with a cheap gate (`DecisionRouter.gate`) *before*
  any expensive per-candidate work.
- Promote surviving candidates to `Finding`s (via the shared decision stages)
  and add them to the injected `KnowledgeBase`.
- Record per-run metrics and a graph/coverage snapshot for the report + UI.

**Non-responsibilities**
- No concrete tools (HTTP proxy, browser, shell, sandbox, PoC generation). Those
  are M3 adapters behind `Tool`; the engine only calls the interface.
- No scoring/dedup/validate math of its own — it reuses `aegis.analysis`.
- No `Candidate`/`Finding`/`KnowledgeBase`/`DecisionRouter` redefinition — it
  imports and composes the M1 types.
- No report formatting/UI, no cross-engine merge (orchestrator's job in M6).
- No network, no cloud, no third-party service; reaches no real target.

## Data model

New types live in `aegis.engines.dynamic`. They compose, never replace, the M1
types (`Candidate`, `Finding`, `Rejection`, `KnowledgeBase`, `DecisionRouter`,
`AegisConfig`).

```python
class AgentRole(str, Enum):           # the specialist personas
    COORDINATOR      = "coordinator"       # root; routes + spawns, files nothing
    RECON            = "recon"             # maps surfaces -> observations + leads
    EXPLOITATION     = "exploitation"      # turns a lead into a Candidate
    POST_EXPLOITATION = "post_exploitation" # chains an accepted Finding further

class AgentStatus(str, Enum):         # mirrors Strix's lifecycle, trimmed
    PENDING = "pending"; RUNNING = "running"; WAITING = "waiting"
    COMPLETED = "completed"; STOPPED = "stopped"; FAILED = "failed"

ACTIVE_STATUSES = frozenset({PENDING, RUNNING, WAITING})
TERMINAL_STATUSES = frozenset({COMPLETED, STOPPED, FAILED})

@dataclass
class AgentNode:
    id: str                       # short deterministic id, e.g. "a0001"
    role: AgentRole
    task: str                     # concrete objective for this agent
    parent_id: Optional[str]      # None for the coordinator root
    status: AgentStatus = AgentStatus.PENDING
    skills: list[str] = []        # advisory skill names (tool selection in M3)
    steps_spent: int = 0
    created_step: int = 0

@dataclass
class Observation:                # a recon fact / lead on the blackboard
    agent_id: str
    surface: str                  # the thing examined, e.g. "/login"
    note: str
    lead: bool = False            # True => a promising place for exploitation

@dataclass
class CoverageEntry:              # honest "what was checked", two provenances
    surface: str
    risk_area: str                # e.g. "sql_injection"
    source: str                   # "agent_reported" | "machine_observed"
    outcome: str                  # "clean" | "candidate" | "inconclusive"
    agent_id: str

@dataclass
class Blackboard:                 # the one shared state for a run
    kb: KnowledgeBase             # the shared store (injected, not owned)
    observations: list[Observation] = []
    claimed_surfaces: set[str] = set()      # work-dedup: who owns which surface
    coverage: list[CoverageEntry] = []
    messages: list[dict] = []     # append-only inter-agent log (deterministic)
    pending_candidates: list[Candidate] = []  # discovered, not yet triaged

@dataclass
class StepBudget:
    max_steps: int = 24           # hard loop bound (termination guarantee)
    max_agents: int = 8           # cap on graph size
    steps_spent: int = 0
    def exhausted(self) -> bool: return self.steps_spent >= self.max_steps

@dataclass
class DynamicEngineConfig:
    roles_enabled: tuple[AgentRole, ...] = (RECON, EXPLOITATION, POST_EXPLOITATION)
    budget: StepBudget = StepBudget()
    triage_kind: str = "dynamic.triage_true_positive"   # DecisionRouter kind
    route_kind: str = "dynamic.route_next_role"         # DecisionRouter kind
    posterior_min: float = DEFAULT_POSTERIOR_MIN
    parallel: bool = True          # batch active agents per step (deterministic order)

@dataclass
class EngineResult:               # what run() returns to the orchestrator
    kb: KnowledgeBase             # the shared store, now populated
    graph: list[AgentNode]        # final agent graph snapshot
    coverage: list[CoverageEntry]
    metrics: dict                 # steps, agents, candidates, triage pass/drop...
```

A `Tool` interface is referenced but defined in M3 (see
`continuation-architecture-map.md` §4). The engine depends only on this shape:

```python
class Tool(Protocol):             # M3 — here only as a dependency contract
    name: str
    kind: str                     # "dynamic"
    def available(self) -> bool: ...
    def run(self, target, **opts) -> "ToolResult": ...   # -> {candidates, ...}
```

Offline, a `SampleProbe` (engine-local, not a public tool) plays the tool's role:
given the bundled sample target it yields a fixed, ordered set of `Candidate`s
(the same shape as `data/sample_findings.json`, carrying `hints` for the static
backend). It performs no I/O beyond reading the bundled fixture.

## Interfaces

```python
class DynamicEngine:
    def __init__(
        self,
        router: DecisionRouter,
        kb: KnowledgeBase,
        config: DynamicEngineConfig | None = None,
        tools: Sequence[Tool] | None = None,   # None => offline SampleProbe
    ) -> None:
        """Compose the engine over a shared router + knowledge base.

        `kb` is shared with the orchestrator and (later) the StaticEngine, so
        findings from every engine land in one store. `tools` is empty offline;
        determinism comes from the router's static backend + SampleProbe.
        """

    def run(self, target: "Target") -> EngineResult:
        """Drive the graph-of-agents loop to termination over `target`.

        `target` is a local/sample descriptor (path or fixture id) — never a
        remote host. Seeds the coordinator + enabled roles, steps the loop until
        the budget is spent / no agent is active / the root finishes, then
        returns the shared KB plus a graph + coverage snapshot. Idempotent given
        the same (router, target): the static backend makes it reproducible.
        """

    # internal, documented so an implementer can test each piece
    def _seed_agents(self) -> None:
        """Create the coordinator root and one agent per enabled role."""

    def _active(self) -> list[AgentNode]:
        """Agents whose status is in ACTIVE_STATUSES, in creation order."""

    def _step(self) -> None:
        """Advance one scheduling step: each active agent takes one action."""

    def _choose_action(self, agent: AgentNode) -> "Action":
        """Pick this agent's next action via DecisionRouter.choose over the
        role's enumerable action set, given a blackboard-derived context."""

    def _triage(self, cand: Candidate) -> bool:
        """Cheap true-positive gate via DecisionRouter.gate, run before any
        expensive per-candidate work. Records a Rejection on a drop."""

    def _promote(self, cand: Candidate) -> Finding | None:
        """Run a surviving candidate through the shared decision stages
        (hypothesis -> dedupe -> validate -> score) and add the Finding to the
        shared KB, or record the Rejection. Returns the Finding or None."""

    def graph_snapshot(self) -> list[AgentNode]:
        """Copy of the current graph for live UI / final report."""
```

`Action` is a small tagged record the role may take, all tool-agnostic:
`SPAWN(role, task)`, `PROBE(surface)`, `TRIAGE(candidate_id)`,
`PROMOTE(candidate_id)`, `MESSAGE(to, text)`, `FINISH`. Which action fires is the
routing decision; what a `PROBE` physically does is a `Tool` in M3 (offline, the
`SampleProbe`).

## Algorithm / control flow

1. **Seed** (`_seed_agents`). Create the `COORDINATOR` root (`parent_id=None`)
   and one `AgentNode` per enabled role as its children. Initialize the
   `Blackboard` wrapping the injected `KnowledgeBase`.

2. **Step loop** — repeat until `budget.exhausted()`, `_active()` is empty, or
   the coordinator reached `FINISH`:
   1. Snapshot the active agents in deterministic creation order. In `parallel`
      mode they form the step's batch; they are still executed in that fixed
      order so the run is reproducible (no wall-clock / thread races — the
      "parallelism" is logical, matching Strix's model without its async
      coordinator).
   2. For each agent in the batch, call `_choose_action`:
      - Build a short context string from the blackboard (claimed surfaces, open
        leads, pending-candidate count, findings so far). Append a machine
        `[ref=...]` tag so the offline static backend is deterministic.
      - Call **`router.choose(config.route_kind, prompt, options)`** where
        `options` is the role's enumerable action set. The chosen option is the
        action. (Open-ended reasoning is *not* routed here — only the bounded
        choice of next action, exactly where Strix spends routing tokens.)
   3. Execute the action:
      - `PROBE`: ask the tool (offline: `SampleProbe`) for `Candidate`s on an
        unclaimed surface; claim the surface; append `Observation`s and an
        `agent_reported` `CoverageEntry`; push new candidates to
        `blackboard.pending_candidates`.
      - `SPAWN`: if under `max_agents`, add a child `AgentNode` (used by the
        coordinator to add an exploitation/post-exploitation specialist for a
        lead). Mirrors Strix `create_agent` but synchronous.
      - `MESSAGE`: append to `blackboard.messages` (the deterministic stand-in
        for Strix's inter-agent inbox / `send_message_to_agent`).
      - `TRIAGE`: pop a pending candidate and run **`_triage`** (below).
      - `PROMOTE`: run a triaged candidate through **`_promote`** (below).
      - `FINISH`: mark the agent `COMPLETED`; a child posts a summary to the
        blackboard (stand-in for `agent_finish`); the coordinator finishing ends
        the loop.
      - Increment `agent.steps_spent`.
   4. `budget.steps_spent += 1`.

3. **Triage gate** (`_triage`, called before any expensive work on a candidate):
   build the triage statement from the candidate's text (reusing
   `aegis.analysis.triage.triage_statement`) and call
   **`router.gate(config.triage_kind, statement)`**. On `False`, record
   `kb.add_rejection(cand, "triage", ...)` and a `clean`/`inconclusive`
   `CoverageEntry`; the candidate never reaches validation/scoring (the
   token/compute-saving hot path). On `True`, keep it for promotion.

4. **Promotion** (`_promote`): hand the survivor to the shared decision stages —
   hypothesis posterior, cross-finding dedupe against `kb.accepted`,
   exploitability validation, CVSS scoring — i.e. the existing
   `aegis.analysis.pipeline` steps 2–5 (step 1, triage, already ran in `_triage`,
   so promotion does not re-triage). Accepted results become `Finding`s added via
   `kb.add_finding`; drops become `Rejection`s. A `POST_EXPLOITATION` agent may
   then `SPAWN`/`PROBE` off an accepted finding to chain further surfaces.

5. **Terminate & report.** `kb.rank()`; assemble `metrics` (steps spent, agents
   created, candidates discovered, triage kept/dropped, promotions, decisions and
   cache hits from `router.metrics`), and return `EngineResult` with the shared
   KB, the graph snapshot, and the coverage ledger.

Every decision in steps 2.2, 3 goes through `DecisionRouter`, so the whole run is
logged (JSONL), cached, threshold-tuned, and replayable — the same guarantee the
pipeline already relies on.

## Testability

- **Deterministic by construction.** With `AegisConfig(backend="static")` the
  router's backend is the `HintBackend` stand-in: `choose` returns a fixed index
  and `gate` resolves from the candidate `hints` via the `[ref=...]` tag. The
  scheduler iterates agents in creation order and the `SampleProbe` yields a
  fixed, ordered candidate set, so a run over the bundled sample is byte-for-byte
  reproducible. No threads, no clocks, no randomness in the control path.
- **Assertable units.** `_triage` returns a plain `bool`; `_choose_action`
  returns a typed `Action`; `_promote` returns `Finding | None`. Each is testable
  in isolation with a hand-built `StaticBackend` whose `boolean_fn`/`choose_fn`
  encode the scenario.
- **Loop-level tests.** Over `data/sample_findings.json`: expect the two SQLi
  entries (`F1`, `F2` with `duplicate_of: F1`) to collapse to one accepted
  finding, the public-test-key false positive (`F3`, low `true_positive_prob`)
  to be dropped at triage, and the loop to terminate within `max_steps`.
  Assert `metrics` counts and `kb.severity_counts()`.
- **Termination guarantee.** `StepBudget.max_steps` bounds the loop regardless of
  routing, so a degenerate backend can never hang a test.
- **Offline always.** The whole suite runs with no network and no model server;
  selecting `basal`/`jev` only swaps the primary backend and keeps `HintBackend`
  as fallback, so tests default to pure-static.

## Local-only notes

- The engine refuses to start unless `AegisConfig.local_only` is satisfied; it
  never constructs a remote decision backend itself (that guard lives in
  `AegisConfig`, which rejects `jev` under `local_only`).
- `target` is always a local path / bundled fixture id. There is no code path
  that resolves a hostname, opens a socket, or reaches a third-party service.
  `PROBE` offline reads only the bundled sample; M3 dynamic tools must likewise
  run against the local/authorized sample (a local sandbox, not cloud).
- Inter-agent messaging is an in-process append-only list, not a broker; the
  "sandbox" a future shell/PoC tool uses is a local process, never hosted.
- The decision log is a local JSONL file (`AEGIS_LOG`); nothing is emitted off
  the machine.

## Open questions / deferred

- **Real parallelism.** M2 uses logical, deterministic batching. If a later
  milestone wants true concurrent tool execution, it must keep a deterministic
  replay mode (seeded order) for tests — decision ordering through the router is
  the thing that must stay stable.
- **Richer routing context.** The context string handed to `choose` is
  deliberately small. A learned/threshold-tuned context (coverage gaps, budget
  remaining) is a calibration question for later, using `router.record_outcome`.
- **Coverage reconciliation.** `machine_observed` coverage (which agents ran,
  how they terminated, skills carried vs risk areas recorded) is sketched but the
  gap-detection rules are deferred to the report milestone (M5).
- **Tool capability negotiation.** How roles map to M3 tools/skills
  (`available()` degradation when a binary is absent) is an M3 concern; here it is
  only an advisory `skills` list on `AgentNode`.
- **Budget policy.** Only a hard stop is specified; a Strix-style pause/resume
  (`budget_paused`) is deferred.

## Upstream patterns credited (for NOTICE)

The following are *patterns and shapes* drawn from upstream behavior, reused in
original code; no upstream source is copied.

- **Strix (Apache-2.0) — graph of agents.** The specialist-role graph with a
  coordinator root, parent/child spawning, per-agent lifecycle statuses
  (running / waiting / completed / stopped / failed), and the step/termination
  discipline. Shape drawn from `strix/core/agents.py` (`AgentCoordinator`,
  `Status`/`ACTIVE_STATUSES`/`TERMINAL_STATUSES`) and
  `strix/tools/agents_graph/tools.py` (`create_agent`, `send_message_to_agent`,
  `wait_for_agents`, `agent_finish`, `view_agent_graph`).
- **Strix — findings triage before expensive work.** The cheap true-positive
  gate run ahead of write-up/PoC. Shape drawn from the triage/escalation
  decisions in `strix/agents/factory.py` and the finish/coverage reconciliation
  step, mapped onto `DecisionRouter.gate`.
- **Strix — shared report/coverage state as a blackboard.** The run-scoped
  product state agents read/write, and the honest `agent_reported` vs
  `machine_observed` coverage ledger. Shape drawn from `strix/report/state.py`
  (`ReportState`) and `strix/report/coverage.py`.
- **Strix — vulnerability-report dedup.** Collapsing a candidate into an already
  filed report for the same underlying vulnerability. Shape drawn from
  `strix/report/dedupe.py`; implemented here via the shared
  `aegis.analysis.dedupe` stage against `KnowledgeBase.accepted`.
- **Routing as a typed choice.** Spending tokens only on the enumerable
  "which specialist / action next" decision while leaving open-ended reasoning
  elsewhere — the division sketched in `aegis.decision.integrations.strix_decisions`.
