# StaticEngine — spec

> Aegis milestone **M2**, static side. See
> [`continuation-architecture-map.md`](../continuation-architecture-map.md)
> §3 (StaticEngine). This is a clean-room spec: behavior described in our own
> words, built on the existing M1 `aegis` core. **Operating constraint:
> local-only** — no hosting, no third-party infra, offline/localhost decision
> backends only.

## Purpose

`StaticEngine` is the RAPTOR-style, hypothesis-driven audit loop. It treats each
potential vulnerability as a *hypothesis* ("this is a genuine, exploitable
finding"), keeps a priority-ordered queue of open hypotheses, gathers evidence
for the one most worth investigating next, tracks which units of the target have
been examined, runs the staged `/validate` exploitability chain, and computes a
posterior/verdict. Hypotheses that clear the floor become `Finding` objects in
the shared `KnowledgeBase`. It is tool-agnostic: concrete scanners (semgrep,
codeql, SCA) arrive in M3 as pluggable evidence providers.

## Responsibilities / non-responsibilities

**Responsibilities**
- Seed hypotheses from input `Candidate`s and assign each a priority score.
- Maintain a deterministic priority queue; investigate highest-priority first.
- Gather and *grade* evidence per hypothesis through pluggable, offline evidence
  providers; record what was examined in a coverage ledger.
- Compute each hypothesis's posterior (reusing `aegis.analysis.hypothesis`).
- Run the eight-stage exploitability chain (reusing `aegis.analysis.validate`).
- Decide a verdict (accept → `Finding`; drop → `Rejection`) and write it to the
  shared `KnowledgeBase`.
- Optionally expand *sibling* hypotheses surfaced by evidence (bounded).
- Report coverage and run metrics.

**Non-responsibilities**
- No concrete static tools of its own (M3). Evidence providers are injected.
- No target execution, no exploitation, no network — reasons over text summaries.
- Does not define `Candidate` / `Finding` / `Rejection` / `KnowledgeBase` /
  `DecisionRouter`; it *reuses* the M1 types.
- No CVSS math or dedup logic of its own — reuses `aegis.analysis.cvss` and
  `aegis.analysis.dedupe`.
- Not the dynamic (Strix) engine; shares only the router + KB with it.

## Data model

Reused from M1 (imported, never redefined):
`aegis.knowledge.models.Candidate`, `Finding`, `Rejection`, `Severity`;
`aegis.knowledge.base.KnowledgeBase`; `aegis.decision.DecisionRouter`;
`aegis.analysis.validate.ValidationResult`; `aegis.config.AegisConfig`.

New types (this subsystem):

```python
class HypothesisStatus(str, Enum):
    QUEUED        = "queued"         # awaiting investigation
    INVESTIGATING = "investigating"  # currently being worked
    ACCEPTED      = "accepted"       # became a Finding
    REJECTED      = "rejected"       # became a Rejection
    EXHAUSTED     = "exhausted"      # budget/iteration cap reached, undecided

class EvidenceConfidence(str, Enum):   # grading, mirrors RAPTOR evidence grade
    HIGH = "high"; MEDIUM = "medium"; LOW = "low"

@dataclass
class EvidenceItem:
    source: str          # provider/tool label, e.g. "static:audit", "semgrep"
    kind: str            # "mechanical" | "inferred"  (verifiable vs LLM-shaped)
    summary: str         # one-line, text-only; appended to Candidate.evidence
    confidence: EvidenceConfidence = EvidenceConfidence.MEDIUM

@dataclass
class Hypothesis:
    candidate: Candidate            # the nascent finding this hypothesis is about
    seq: int                        # monotonic insertion index (deterministic tie-break)
    priority: float = 0.0           # 0..10, higher = investigate first
    status: HypothesisStatus = HypothesisStatus.QUEUED
    evidence: list[EvidenceItem] = field(default_factory=list)
    posterior: Optional[float] = None
    validation: Optional[ValidationResult] = None
    parent_id: Optional[str] = None # set for sibling/derived hypotheses
    @property
    def id(self) -> str: return self.candidate.id

@dataclass
class StaticEngineConfig:
    posterior_min: float = DEFAULT_POSTERIOR_MIN  # from aegis.config
    priority_min: float = 0.0        # drop hypotheses scoring below this (0..10)
    max_iterations: Optional[int] = None  # None → drain the queue
    max_hypotheses: int = 256        # hard cap incl. sibling expansion (termination)
    enable_triage: bool = True       # reuse Strix triage gate as a cheap pre-filter
    enable_dedupe: bool = True       # reuse dedupe against KB.accepted
    enable_siblings: bool = False    # bounded sibling-hypothesis expansion (M2 default off)
```

`CoverageLedger` — a component-keyed record of what has been examined (the M2,
tool-agnostic analogue of RAPTOR's file/line coverage store):

```python
@dataclass
class CoverageLedger:
    examined: dict[str, set[str]] = field(default_factory=dict)  # component -> {tool labels}
    def mark(self, component: str, tool_label: str) -> None: ...
    def is_examined(self, component: str) -> bool: ...
    def gaps(self, all_components: Iterable[str]) -> list[str]: ...   # never examined
    def summary(self) -> dict: ...  # {"examined": n, "by_tool": {...}}
```

`EvidenceProvider` — the pluggable, offline evidence source (M3 wraps real
tools behind this; M2 ships the hint-driven default):

```python
@runtime_checkable
class EvidenceProvider(Protocol):
    name: str
    def gather(self, hyp: Hypothesis) -> list[EvidenceItem]: ...
```

## Interfaces

```python
class StaticEngine:
    def __init__(self, router: DecisionRouter,
                 kb: Optional[KnowledgeBase] = None,
                 config: Optional[StaticEngineConfig] = None,
                 providers: Optional[Sequence[EvidenceProvider]] = None) -> None:
        """Bind the shared router + KnowledgeBase (a fresh KB if None).
        `providers` default to [HintEvidenceProvider()] so a run is fully
        offline and deterministic. All model calls go through `router`."""

    def seed(self, candidates: Sequence[Candidate]) -> int:
        """Wrap each Candidate in a Hypothesis, score its priority, and enqueue
        it. Returns the number seeded. Idempotent per candidate id."""

    def score_priority(self, hyp: Hypothesis) -> float:
        """Return 0..10 'worth investigating next' score via
        router.score("static.hypothesis.priority", <statement [ref=id]>, 0, 10).
        Optionally blended with a mechanical attack-surface prior read from
        candidate.metadata (entry_point / sink / trust_boundary flags)."""

    def gather_evidence(self, hyp: Hypothesis) -> list[EvidenceItem]:
        """Run each provider, collect + grade evidence, append each item's
        summary to hyp.candidate.evidence (so posterior/validate see it), and
        mark hyp.candidate.component examined in the coverage ledger per
        provider. Returns the new items."""

    def compute_posterior(self, hyp: Hypothesis) -> float:
        """P(hypothesis true | evidence) in [0,1] via
        aegis.analysis.hypothesis.posterior(self.router, hyp.candidate)."""

    def validate(self, hyp: Hypothesis) -> ValidationResult:
        """Run the eight-stage exploitability chain via
        aegis.analysis.validate.validate_exploitability(self.router,
        hyp.candidate)."""

    def investigate(self, hyp: Hypothesis) -> Optional[Finding]:
        """One full hypothesis cycle (see control flow). Writes a Finding or a
        Rejection to the KB and sets hyp.status. Returns the Finding or None."""

    def run(self) -> KnowledgeBase:
        """Drain the queue (bounded by config), rank the KB, attach metrics,
        and return the shared KnowledgeBase."""

    def coverage(self) -> CoverageLedger: ...
    def pending(self) -> list[Hypothesis]: ...   # snapshot of the queue
```

`HypothesisQueue` (internal): `push(hyp)`, `pop() -> Hypothesis`,
`requeue(hyp)`, `__len__`. Ordering is **priority descending, then `seq`
ascending** — a total order, so draining is deterministic.

`HintEvidenceProvider` (default, offline): derives `EvidenceItem`s from
`candidate.evidence` and `candidate.hints` (e.g. an `evidence_strength` hint →
one graded item), labeled `"static:hint"`. Purely local, no I/O.

## Algorithm / control flow

`seed(candidates)`
1. For each candidate not already seeded: build a `Hypothesis(seq=next)`.
2. `priority = score_priority(hyp)` → **`DecisionRouter.score`**
   (`"static.hypothesis.priority"`, scale 0..10). The statement carries
   `[ref=<id>]` so the static backend resolves it deterministically.
3. If `priority < config.priority_min`, record a `Rejection(stage="priority")`
   and skip; else `queue.push(hyp)`.

`run()` loop (the review–sweep–record cycle):
```
iters = 0
while queue and (max_iterations is None or iters < max_iterations):
    hyp = queue.pop()                      # highest priority, oldest seq
    hyp.status = INVESTIGATING
    investigate(hyp)                       # writes KB, may enqueue siblings
    iters += 1
# anything still queued when the cap hits is marked EXHAUSTED (undecided,
# recorded as a Rejection(stage="budget")) — never silently dropped.
kb.rank(); kb.metrics = {...}; return kb
```

`investigate(hyp)` (per-hypothesis stage order; each gate is a typed decision):
1. **Evidence** — `gather_evidence(hyp)`; marks coverage. (No model call in the
   offline default; providers may call the router in M3.)
2. **Triage** (optional, cheap) — reuse `aegis.analysis.triage.is_true_positive`
   → **`DecisionRouter.gate("triage.true_positive")`**. Fail → `Rejection`.
3. **Posterior** — `compute_posterior(hyp)` → **`DecisionRouter.score`** inside
   `aegis.analysis.hypothesis`. Below `posterior_min` → `Rejection(stage="hypothesis")`.
4. **Dedupe** (optional) — reuse `aegis.analysis.dedupe.find_duplicate` against
   `kb.accepted` → **`DecisionRouter.gate("dedupe.same_vuln")`**. Hit →
   `Rejection(stage="dedupe")`.
5. **Validate** — `validate(hyp)`; the eight-stage chain short-circuits on the
   first failing gate (**`DecisionRouter.gate("validate.stage")`** ×8). A
   non-exploitable result is *not* a rejection — it is recorded as an
   informational finding (RAPTOR originate-not-refute doctrine).
6. **Score + verdict** — CVSS base score + band via `aegis.analysis.cvss`;
   derive a verdict tier from the strongest evidence grade and the validation
   outcome (CONFIRMED if an exploitable chain + mechanical HIGH evidence, down
   to SPECULATIVE); store the tier in `candidate.metadata["verdict_tier"]`.
   Build a `Finding(candidate, posterior, cvss_score, severity, exploitable,
   stages_passed, failed_stage)` and `kb.add_finding(...)`; set
   `hyp.status = ACCEPTED`.
7. **Sibling expansion** (optional, bounded) — if evidence named adjacent
   suspect components and `len(seeded) < max_hypotheses`, build child
   hypotheses (`parent_id=hyp.id`), apply a bounded priority boost, and enqueue.
   Visited-id set + `max_hypotheses` guarantee termination.

Every branch in steps 2–5 is a typed call through the single `DecisionRouter`,
so the whole run is thresholded, cached, logged (JSONL), and replayable.

## Testability

Deterministic and fully offline with the **`static` backend**
(`aegis.analysis.backends.build_router` → `HintBackend`), which resolves each
decision from the candidate's `hints` via the `[ref=...]` tag the reused stages
already append:
- Fixtures set `hints` (`true_positive_prob`, `evidence_strength`,
  `exploit_stages_pass`, `duplicate_of`) → priority, posterior, triage, dedupe,
  and each validation stage are fixed, so `kb.accepted` / `kb.rejected`,
  per-hypothesis `status`, `stages_passed`, and `failed_stage` are all exactly
  assertable.
- Queue order is a documented total order (priority desc, seq asc) → the exact
  investigation sequence is assertable; no wall-clock or hashing in ordering.
- `max_iterations` lets a test stop mid-drain and assert the `EXHAUSTED`
  remainder and the `coverage()` ledger.
- The router's JSONL decision log is the replay/calibration oracle (kind,
  probability, threshold, backend) — assert the decision trail per hypothesis.
- No network, no target, no binary, no real tool: `HintEvidenceProvider` does
  pure in-memory derivation. M3 providers are injected and can be stubbed.

## Local-only notes

- Default backend is offline (`static`); `basal` is localhost-only; the remote
  `jev` backend is refused unless `local_only` is explicitly disabled
  (`AegisConfig` guard). The engine never selects a backend itself — it takes a
  `DecisionRouter` built by `aegis.analysis.backends`.
- Evidence providers must be offline or localhost (local file reads, a local
  sandbox, a localhost model server). No hosted services, no egress. A provider
  that would require a hosted service is recorded unavailable and routed around
  (per the M3 tool-interface contract), never silently reaching out.
- Decision logs and coverage are written to local paths only.

## Open questions / deferred

- **Cross-run verdict reuse** (RAPTOR `verdict_reuse`): import a prior run's
  verdict at zero cost when the component's content hash is unchanged. Deferred;
  needs a content-hash key the M2 component string does not yet carry.
- **Line-level coverage**: M2 coverage is component-keyed. File/line-interval
  coverage (and gap ranking from it) waits on the M3 tools that produce spans.
- **Per-stage validate thresholds**: `raptor_gates.RAPTOR_VALIDATE_THRESHOLDS`
  defines per-stage thresholds; M2 reuses the single `validate.stage` threshold.
  Whether to adopt per-stage thresholds (and surface them in `AegisConfig`) is
  open.
- **Sibling expansion default**: off in M2 pending a real provider that emits
  adjacency; the mechanism and termination bounds are specified so M3 can flip
  it on.
- **Mechanical priority prior**: blending an attack-surface prior into
  `score_priority` depends on providers populating `candidate.metadata`; the
  blend weight is unspecified until there is data to calibrate it.

## Upstream patterns credited (for NOTICE)

Behavioral patterns drawn on (shape only; no code copied). Framework: **RAPTOR**
(MIT, `github.com/gadievron/raptor`).
- **Hypothesis-driven audit loop** — the review→evidence→validate→record cycle
  driven by a priority queue (shape of `core/audit/orchestrator.py`,
  `core/audit/pipeline.py`).
- **Attack-surface priority scoring** — "higher score = review first", ties by
  size (shape of `core/audit/priority.py`).
- **Coverage ledger / gap queue** — mark-what-was-examined and derive gaps
  (shape of `core/coverage/store.py`, `core/audit/gaps.py`).
- **Hypothesis seeds as hints, never verdicts; bounded priority boost; sibling
  expansion** (shape of `core/audit/hypothesis_intake.py`).
- **Evidence grading** — mechanical-vs-inferred source tags and HIGH/MEDIUM/LOW
  confidence; a finding's grade is the strongest in its chain (shape of
  `core/audit/evidence_grade.py`, `core/evidence/`).
- **Staged `/validate` exploitability chain** — ordered yes/no gates that
  short-circuit on first failure (shape of `core/audit/validate.py`; already
  modeled in `aegis.decision.integrations.raptor_gates` /
  `aegis.analysis.validate`).
- **Verification tiers cap severity** — CONFIRMED / TOOL_BACKED / LLM_ONLY /
  SPECULATIVE (shape of `VerificationTier` in `core/audit/pipeline.py`).
- **Originate-not-refute doctrine; frontier records for partial coverage** —
  a non-exploitable result is informational, not a refutation (shape of
  `core/taint/engine.py`).
- **Path-constraint satisfiability as a validation stage** — the "constraints
  satisfiable" gate is grounded in SMT path-feasibility (shape of
  `core/smt_solver/path_feasibility.py`, `core/audit/path_feasibility.py`).
- **Cross-run verdict reuse** (deferred) — shape of
  `core/audit/verdict_reuse.py`.
