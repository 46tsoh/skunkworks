# Tool interface — spec

> Aegis milestone **M3 foundation**, specced now (ahead of its build) so the M2
> engines — `DynamicEngine` (Strix-style graph-of-agents) and `StaticEngine`
> (RAPTOR-style hypothesis-driven audit) — are written against a stable tool
> contract. See [`continuation-architecture-map.md`](../continuation-architecture-map.md)
> §2 (unified architecture) and §4 (tool interface).

## Purpose

Define the single abstraction through which *both* engines invoke every
capability — dynamic (proxy, browser, shell, sandbox, recon, SAST, DAST, PoC)
and static (semgrep, codeql+SMT, SCA/SBOM, binary, fuzzing, crash, frida, web
endpoint, forensics). A `Tool` turns heterogeneous capabilities into one uniform
`run(target, **opts) -> ToolResult` call so the orchestrator and engines stay
tool-agnostic. Capabilities that wrap an external binary degrade to a clear,
recorded "unavailable" result when the binary is absent instead of crashing the
run, and offline/fixture-driven adapters ship first so the whole pipeline is
testable with no binaries and no network.

## Responsibilities / non-responsibilities

Responsibilities:
- Provide `Tool`, `ToolResult`, `ToolStatus`, `Artifact`, and `ToolRegistry`.
- Normalise every capability's native output into `Candidate` objects (the
  existing `aegis.knowledge.models.Candidate`) plus raw output and artifacts.
- Detect binary availability and model absence as data (an `UNAVAILABLE`
  result), never an exception that aborts an engine.
- Give a deterministic, offline execution path (fixture adapters) for tests.
- Be the only place that shells out, opens a socket, or touches a target.

Non-responsibilities:
- No triage / dedup / exploitability / scoring — that is the `aegis.analysis`
  pipeline via `DecisionRouter`. Tools *produce* `Candidate`s; they do not
  accept/reject them or compute CVSS scores or posteriors.
- No orchestration — the engines (M2) decide *which* tools to run and *when*.
- No `Finding`/`Rejection` creation and no `KnowledgeBase` writes — the pipeline
  owns those types and the store.
- No network egress for decisions and no remote hosting (local-only; see below).

## Data model

Reuses the M1 knowledge types unchanged: `Candidate`, and (downstream, not here)
`Finding`, `Rejection`, `KnowledgeBase` from `aegis.knowledge`. A tool's job ends
at emitting `Candidate`s.

```python
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol
from aegis.knowledge.models import Candidate

class ToolKind(str, Enum):
    DYNAMIC = "dynamic"   # runs against a live/authorized target
    STATIC  = "static"    # reads source / artifacts, no live target

class ToolStatus(str, Enum):
    OK          = "ok"           # ran, result meaningful (may be 0 candidates)
    UNAVAILABLE = "unavailable"  # binary/dependency absent; nothing ran
    ERROR       = "error"        # ran and failed (bad input, crash, timeout)
    SKIPPED     = "skipped"      # precondition not met (e.g. wrong target kind)

@dataclass
class Artifact:
    """A file a tool produced (SARIF, pcap, screenshot, SBOM, PoC script, core
    dump). Lives under the run's local artifacts dir; never uploaded."""
    kind: str                       # "sarif" | "pcap" | "screenshot" | "sbom" | ...
    path: Path                      # local path inside the run dir
    label: str = ""
    media_type: str = ""            # e.g. "application/json", "image/png"
    metadata: dict = field(default_factory=dict)

@dataclass
class ToolResult:
    """The uniform return of every Tool.run(). Carries produced candidates, the
    raw tool output (for the audit trail / UI), on-disk artifacts, and errors."""
    tool: str                       # Tool.name that produced this
    status: ToolStatus
    candidates: list = field(default_factory=list)   # list[Candidate]
    raw: str = ""                   # captured stdout/stderr or serialized native output
    artifacts: list = field(default_factory=list)    # list[Artifact]
    errors: list = field(default_factory=list)       # list[str], human-readable
    duration_ms: float = 0.0
    target: str = ""                # what was analysed (echoed back)
    metadata: dict = field(default_factory=dict)     # exit code, binary version, fixture id

    @property
    def ok(self) -> bool: ...        # status is OK
    @property
    def ran(self) -> bool: ...       # status in {OK, ERROR}
    def as_dict(self) -> dict: ...   # JSON-safe (candidates -> ids+titles, paths -> str)
```

`Candidate.source_engine` is set by the engine, but every tool stamps its own
name into `Candidate.metadata["tool"]` and `Candidate.evidence` so provenance
survives into the unified report. Fixture adapters may populate
`Candidate.hints` (sample ground truth) exactly as M1 intends — the static
decision backend reads `hints`, real backends ignore it.

## Interfaces

```python
class Tool(Protocol):
    name: str                       # unique registry key, e.g. "semgrep"
    kind: ToolKind
    requires_binary: Optional[str]  # external executable name, or None if pure-python/fixture

    def available(self) -> bool:
        """True if this tool can run now. Fixture/pure-python adapters return
        True unconditionally; binary adapters return shutil.which(requires_binary)
        is not None (optionally a version probe). Must not raise and must not run
        the target."""

    def run(self, target: str, **opts) -> ToolResult:
        """Execute against `target` (a path, URL, or sample id) and return a
        ToolResult. MUST NOT raise for the common failure modes: if available()
        is False, return status=UNAVAILABLE with an explanatory error and zero
        candidates; on tool crash/timeout/bad-input return status=ERROR with the
        message in errors[]. Deterministic given the same target+opts for fixture
        adapters."""
```

```python
class BinaryBackedTool:
    """Base for binary adapters. Subclasses implement _run_binary() (builds argv,
    runs it locally, parses output into candidates). available() is the binary
    probe; run() wraps _run_binary() so absence -> UNAVAILABLE and any exception
    -> ERROR, uniformly. Each ships a sibling fixture adapter that parses a
    recorded output file so behaviour is pinned without the binary present."""
    def _run_binary(self, target: str, **opts) -> ToolResult: ...

class FixtureTool:
    """Wraps a recorded native-output file (SARIF, JSON, pcap summary, HAR) under
    tests/fixtures/<tool>/ and parses it with the SAME parser the binary adapter
    uses, yielding identical Candidates offline. This is the default-registered
    variant until a binary is confirmed present locally."""
    def __init__(self, name, kind, fixture_path, parser): ...
```

```python
class ToolRegistry:
    """Name -> Tool map the engines query. Holds both dynamic and static tools;
    engines filter by kind and availability."""
    def register(self, tool: Tool) -> None: ...        # unique name or ValueError
    def get(self, name: str) -> Tool: ...              # KeyError if absent
    def by_kind(self, kind: ToolKind) -> list: ...     # list[Tool]
    def available(self, kind: Optional[ToolKind] = None) -> list: ...  # .available() is True
    def run(self, name: str, target: str, **opts) -> ToolResult: ...   # get + run
    def status_report(self) -> dict: ...  # {name: {kind, requires_binary, available}} for STATUS.md / UI

def default_registry(config) -> ToolRegistry:
    """Build the standard registry from AegisConfig. Fixture adapters register
    first; a binary adapter registers under the same name ONLY if its binary is
    present (else the fixture keeps the slot), so a fresh checkout is fully
    exercisable offline."""
```

## Algorithm / control flow

Per tool invocation, inside `ToolRegistry.run(name, target, **opts)`:

1. `get(name)` → `Tool` (raises `KeyError` only for an unknown name, which is a
   wiring bug, not a runtime condition).
2. `tool.available()` — binary adapters probe `shutil.which(requires_binary)`
   (and optionally a cached `--version`); fixture/pure-python adapters return
   `True`. If `False`: return `ToolResult(status=UNAVAILABLE, errors=["<binary>
   not found; install locally or run the fixture adapter"])`. The engine
   **records** this (it becomes a note in the run and a row in
   `status_report()`) and **routes around** it — no exception.
3. If available, `tool.run(target, **opts)` executes locally (subprocess for
   binaries; direct parse for fixtures), under the run's artifacts dir. All
   exceptions caught at the `BinaryBackedTool.run` boundary → `status=ERROR`,
   message in `errors[]`, candidates `[]`.
4. Parse native output → `Candidate` list (cwe, component, cvss_vector,
   description, evidence). Write produced files as `Artifact`s under the run
   dir. Capture stdout/stderr into `raw`. Stamp `duration_ms`, exit code and
   binary version into `metadata`.
5. Return the `ToolResult` to the calling engine.

**Where DecisionRouter and KnowledgeBase enter (they do not, here):** tools
never call `DecisionRouter` or touch `KnowledgeBase`. The boundary is strict:

```
Tool.run → ToolResult.candidates ─┐
                                   ├─► Engine (M2) collects candidates
                                   │   then calls aegis.analysis.pipeline.run(...)
                                   ▼
        aegis.analysis.pipeline ── uses ──► DecisionRouter  (triage/hypothesis/dedupe/validate)
                                   └─ writes ─► KnowledgeBase (Finding / Rejection, ranked)
```

So an `UNAVAILABLE`/`ERROR` tool simply contributes no candidates; the router
and KB see fewer inputs but run unchanged. This keeps the one-choke-point and
one-store invariants from the architecture map intact: tools widen the funnel,
the router and KB remain the only decision/storage points.

Engine-side loop (informative, built in M2): for each selected tool →
`registry.run(...)` → append `result.candidates` and note `result.status` and
`artifacts` → after all tools, hand the pooled candidates to the pipeline, which
drives the router and writes the shared KB.

## Capability set to implement (one-line ToolResult contract each)

Each is registered fixture-first; the binary adapter takes over when its binary
is present locally. "candidates" below are `Candidate` objects.

**Dynamic (`ToolKind.DYNAMIC`):**
- **HTTP intercept proxy** — candidates for issues seen in intercepted traffic
  (reflected params, auth/CORS/header weaknesses); `raw` = request/response
  summaries; artifacts: a captured-traffic/HAR file. `requires_binary` = proxy
  engine (fixture: recorded traffic).
- **Browser automation** — candidates for DOM/client-side issues (XSS sinks,
  mixed content, exposed secrets in JS); `raw` = navigation log; artifacts:
  screenshots + page HTML. `requires_binary` = headless browser (fixture:
  recorded DOM/screenshot).
- **Shell/command exec** — candidates derived from a scripted command run
  against the target (e.g. a scanner CLI); `raw` = stdout/stderr; artifacts:
  command log. Local subprocess only, within the run sandbox.
- **Python sandbox** — candidates confirmed by a short validation script run in
  a resource-limited local subprocess; `raw` = script output; artifacts: the
  script + its result. No network; CPU/time/memory capped.
- **Recon / OSINT** — candidates for exposed surface (open ports/services,
  subdomains, tech fingerprints) from *local* probing of the authorized target;
  `raw` = probe summary; artifacts: a host/service inventory. No third-party
  OSINT APIs (local-only).
- **SAST** — candidates from source pattern analysis of the target tree (shared
  with the static semgrep engine); `raw` = rule hits; artifacts: SARIF.
- **DAST** — candidates from active request-based testing of a running target
  (injection/traversal probes against authorized endpoints); `raw` = probe
  transcript; artifacts: request/response evidence bundle.
- **PoC generation** — candidates annotated with a generated proof-of-concept
  (the candidate carries the PoC in `evidence`/`metadata`); `raw` = the PoC
  body; artifacts: the runnable PoC script. Proves, does not score.

**Static (`ToolKind.STATIC`):**
- **semgrep** — candidates from rule matches over source (file/line, cwe from
  rule metadata); `raw` = match summary; artifacts: SARIF.
- **codeql + SMT** — candidates from dataflow queries whose path feasibility is
  checked by a local SMT solver (infeasible paths dropped before emission);
  `raw` = query + feasibility notes; artifacts: SARIF + path trace.
- **SCA / SBOM** — candidates for vulnerable/outdated dependencies (CWE-1104
  class) from a locally built dependency graph; `raw` = component list;
  artifacts: SBOM (CycloneDX/SPDX-style JSON). Local CVE/advisory data only.
- **Binary analysis** — candidates from inspecting a binary artifact (unsafe
  imports, missing hardening flags, risky call sites); `raw` = inspection
  summary; artifacts: a facts/fingerprint JSON.
- **Fuzzing** — candidates for inputs that trigger faults in a local harness;
  `raw` = run stats (execs, coverage); artifacts: crashing inputs corpus.
  Time-boxed, local.
- **Crash analysis** — candidates classifying a crash/core as a vuln class
  (bucket, exploitability hint); `raw` = triage summary; artifacts: a crash
  report. Consumes fuzzing/crash artifacts.
- **Frida-style instrumentation** — candidates from runtime hooks on a locally
  launched process (observed sinks, tainted calls); `raw` = hook trace;
  artifacts: an instrumentation log. Local process only.
- **Web endpoint testing** — candidates per discovered endpoint from enumerating
  and exercising a target's routes locally; `raw` = endpoint table; artifacts:
  per-endpoint request/response records.
- **oss-forensics / git-history** — candidates from mining the target repo's
  history (secrets introduced/removed, security-fix commits, vuln-reintroduction);
  `raw` = commit findings; artifacts: an annotated history report. Reads the
  local clone only.

## Testability

- **Fixture-first.** Every capability ships a `FixtureTool` that parses a
  recorded native-output file with the *same* parser the binary adapter uses.
  Tests assert on the resulting `Candidate`s without any binary installed, so
  the parser (the bug-prone part) is covered deterministically.
- **Deterministic by construction.** Fixture adapters are pure functions of
  (fixture file, target id, opts): identical inputs → identical `ToolResult`.
  Candidates carry `hints` so the `StaticBackend` (M1) yields reproducible
  pipeline outcomes end-to-end with no network and no model.
- **Availability is data.** `available()` is tested both ways: force the binary
  "absent" (monkeypatch `shutil.which` → None) and assert `run()` returns
  `UNAVAILABLE` with zero candidates and a populated `errors[]` — never raises.
  A fault injected into a binary adapter asserts `ERROR` with the message
  captured, not propagated.
- **Registry contract.** `default_registry()` built under the `static` backend
  registers a runnable (fixture) tool for every name, so an engine smoke test
  can `run` the full set offline and confirm candidates flow into the pipeline.
- **No egress in tests.** A test guard asserts no adapter opens a non-localhost
  socket; `requires_binary` tools are exercised through fixtures in CI.

## Local-only notes

- The Python sandbox, shell exec, fuzzing, instrumentation and crash analysis
  run as **local subprocesses** with resource caps; no container registry pull
  or remote executor. Nothing is hosted.
- Dynamic tools run **only against the bundled sample or an explicitly
  authorized target**; recon/OSINT and DAST do no third-party API calls and no
  internet scanning — local probing of the authorized target only.
- SCA/SBOM and forensics use **local** advisory/CVE data and the local clone; no
  remote advisory service is contacted at run time.
- Consistent with `AegisConfig.local_only`: tools never perform network egress
  for decisions (that is the router's concern and is already guarded). Artifacts
  are written under the run directory and never uploaded. The UI that surfaces
  `status_report()` and artifacts is a local dev server.

## Open questions / deferred

- **Async / parallelism.** The dynamic engine runs agents in parallel; `run()`
  is specified synchronously. Deferred: whether `ToolRegistry` exposes an async
  variant or the engine parallelises across threads with the registry staying
  sync. Tools must be thread-safe or declare `concurrent = False`.
- **Streaming progress.** The live UI wants per-tool progress; `ToolResult` is
  terminal. Deferred: an optional progress callback / event stream on `run()`.
- **Artifact lifecycle & size caps.** Retention, max size, and redaction of
  captured traffic/screenshots that may contain secrets — deferred to the
  reporting/UI milestone.
- **opts schema.** Per-tool `**opts` are free-form now; a typed per-tool options
  schema (for the UI to render controls) is deferred.
- **Target typing.** `target: str` covers path/URL/sample-id; a richer `Target`
  type (kind + authorization token) may be introduced if engines need to assert
  authorization per tool.
- **Binary version pinning.** How strictly `available()` enforces a minimum
  binary version (vs. presence only) is deferred to each adapter.

## Upstream patterns credited (for NOTICE)

- **Strix (Apache-2.0)** — the *toolbelt* shape (HTTP intercept proxy, browser
  automation driven via command exec, shell `exec_command`, a Python sandbox for
  writing+running validation code, recon, SAST/DAST) and the *reporting-tool*
  shape that files structured findings with CVSS/dedup. Aegis draws on the
  *pattern* of a uniform, host-side tool wrapper returning structured results and
  of PoC-to-prove-a-finding; the implementation and the `Tool`/`ToolResult`
  abstraction are original.
- **RAPTOR (MIT)** — the *static/deep engine toolset* shape (Semgrep rule+analysis
  pipeline, CodeQL queries with SMT path-feasibility, SCA/SBOM dependency
  inventory, binary analysis facts, fuzzing/crash witnesses, frida-style dynamic
  instrumentation, web endpoint testing, and git-history/oss-forensics), its
  *detector-result / prepared-input* separation, and its mechanical `--no-llm`
  offline mode that Aegis mirrors with fixture adapters + the `StaticBackend`.
  Patterns only; no RAPTOR source is reproduced.
