# Interactive shell — `aegis shell`

*Aegis milestone 22. Clean-room: a Strix-style interactive REPL over the
existing dynamic agent loop, written from a reading of Strix's interactive
terminal shape (`strix/interface/tui/`) — original code, local-only.*

## Why

Every other `aegis` subcommand runs to completion and exits. Strix's defining
feel is **interactive**: the operator types a goal, watches the agent think /
act / stream its transcript, and steers it with follow-up instructions. This
milestone adds that surface without hosting anything and without loosening a
single authorization gate.

It deliberately does **not** rewrite `DynamicEngine.run` into a stepwise state
machine (the "start/step/finalize" refactor). That is the higher-parity,
higher-risk path and is left as a named follow-up (§ Deferred). This milestone
reuses the loop as-is and makes the REPL the interactive layer around it.

## Shape

`aegis shell` opens a prompt and reads one command per line from stdin until
`exit`/`quit`/EOF. It holds **session state** — a loaded engagement scope, the
operator's one-time `--authorized` assertion, the run config, one long-lived
event sink, and a session knowledge base — for the life of the process. The
agent loop never receives a reference to that session state (see § Safety).

### Command grammar (closed vocabulary)

The grammar is a fixed set of verbs. Operator free text only ever appears as a
natural-language *instruction* folded into the loop's prompt state, or as a
*target*/*param* string passed **verbatim** to the scope gate. No verb reaches a
shell/command string, and no verb can change an authorization decision.

| verb | effect | live? |
|------|--------|-------|
| `help` | print the grammar | no |
| `scope` | print the frozen engagement scope | no |
| `status` | session counters: steps, unprobed/pending/accepted, authorized, engagement | no |
| `findings` | list the session KB's accepted findings (ranked) | no |
| `transcript` | replay the session event buffer | no |
| `goal <text>` | narrate the dynamic loop over the in-hand candidate pool; `<text>` folds into the loop state | **no** (offline, no network) |
| `focus <surface>` | reorder the candidate pool so `<surface>` is probed first on the next `goal` | no |
| `run [path]` | offline analysis over a **local** path (rejects anything not an existing local path) | no |
| `scan <target> [tool]` | live scanner against `<target>` through the dynamic loop | **yes** |
| `attempt <type> <target> <param>` | stage-1 red-team confirm (`<type>` ∈ xss\|sqli\|redirect\|cmdi\|traversal\|ssti) | **yes** |
| `exit` / `quit` / EOF | leave (rc 0) | — |

An unknown command prints a hint and the REPL stays open (never exits non-zero
mid-session).

## Safety — the center of gravity

A persistent shell turns `--authorized` from a per-invocation confirmation into
a session-wide assertion. The map surfaced a real latent bypass: `_cmd_scan`
(cli.py) checks only `--authorized` + "not a local path", with **no**
`EngagementScope.check()`. Reused naively in a session, one `--authorized` would
let a typed goal reach any host. The shell closes this structurally.

1. **One gate, at the dispatcher.** Every **live** verb (`scan`, `attempt`) is
   flagged in the verb table and funnels through a single
   `_gate(session, target) -> (ok, reason)` chokepoint *before* any network
   action. A future live verb that forgets to set the flag cannot reach the
   network. `_gate` checks, in order:
   - `session.authorized` is `True` (the one-time operator assertion), else refuse;
   - `session.scope.check(target).in_scope` is `True`, else refuse.
   `check()` **returns** a decision and never raises on refusal, so the gate
   branches on `decision.in_scope` — never `try/except`. A refusal prints the
   reason, emits a `scope_refused` event, and the REPL continues (fail-closed).

2. **Scope loaded once, frozen, out-of-band.** `load_scope(args.scope)` runs
   once at startup; a `ScopeError` prints and returns `2` **before** the REPL
   opens. With no `--scope`, the session gets a default-deny `EngagementScope()`
   that authorizes nothing — offline verbs work, every live verb refuses. The
   frozen scope is never rebuilt or reloaded from any typed input.

3. **The agent loop can never widen its own authority.** `engine.run` is called
   with only `(target, kb, router, config, sink)`. It gets no reference to the
   session's `authorized` flag or scope object. A typed goal therefore cannot
   set/flip `--authorized`, set `--allow-egress`, select `backend=jev`
   (also refused under `local_only`), reload scope, or enable
   `allow_post_exploit`/`allow_lateral` (those live only in the frozen scope
   file, default off).

4. **Offline verbs are structurally offline.** `goal`/`focus`/`run` construct
   the narration engine with **no registry** and never set `self._probe`, so
   `DynamicEngine.run` builds a `SampleProbe` over the in-hand candidate pool —
   no `RegistryProbe`, no `tool.run`, no socket. `run [path]` additionally
   rejects any target that is not an existing local path (the inverse of
   `scan`). A test asserts zero tool runs and an empty pool for an arbitrary
   non-path target.

5. **Clamp and verbatim.** `attempt`'s `<type>` is clamped to
   `{xss,sqli,redirect,cmdi,traversal,ssti}` before `RedTeamEngine.attempt`
   (`technique_for` returns `None` otherwise → not attempted). The `<target>` is
   passed byte-for-byte to `scope.check()`/`attempt()` — never pre-resolved or
   rewritten, so scope's userinfo/backslash/path-param defenses see the real
   bytes.

6. **Hostile output is sanitized at the terminal.** The live renderer runs every
   target-derived field (`tool_output.summary`, `message.text`, `finding.title`,
   proof/evidence) through `sanitize_text` before printing, exactly as
   `_cmd_exploit` does — a hostile target string cannot inject terminal control
   sequences.

### `aegis scan` retrofit (non-breaking)

`aegis scan` gains an **optional** `--scope`. When present, the target is run
through `scope.check()` before the Docker tool starts — closing the bypass for
the one-shot command too, as defense in depth. When absent, today's contract
(`--authorized` + not-a-local-path, a single named target asserted in the same
breath) is unchanged, so every documented example and the existing scan test
keep working. The shell, by contrast, **always** gates, because its
`--authorized` is session-wide.

## Streaming

`EventSink` gains one additive field `on_emit: Optional[Callable[[dict], None]]`,
invoked inside `emit()` under the existing lock after the event is appended
(~4 lines; default `None` preserves all current behavior, `NullSink`
untouched). The shell builds **one** long-lived `EventSink` at session start
(it truncates its JSONL on construction, so constructing once is what keeps the
transcript accumulating) with `on_emit` pointed at the terminal renderer, and
`set_event_sink`s it on each per-command engine. The engine is driven
**synchronously in the main thread** (never `Orchestrator.run`, which overwrites
the sink, swallows exceptions in a thread pool, and double-runs registry tools),
so `on_emit → render → print` is single-threaded and strictly ordered.

The renderer is **format/print only**: it is wrapped in `try/except` so a render
error can never break the loop or the JSONL write, and it **never** calls
`sink.emit` (no re-entrancy under the held lock). Red-team `attempt` events are
emitted from the dispatcher thread (outside any `on_emit`), so their
`on_event → sink.emit → on_emit → render` path is one level deep, not nested.
Spawn events are de-duplicated **per command** (the seen-set resets each command)
so genuinely new subagents in later commands are not hidden.

## Driving the loop

`ShellSession(DynamicEngine)` (the `_ExternalScanEngine` precedent) overrides:

- `enumerate_candidates(target, config)` → returns the **current** command's
  pool (`self._pool`), never reads disk, never wires a registry;
- `_context(kb, unprobed, pending)` → `DynamicEngine._context(...)` (the base
  staticmethod) plus the folded instruction `self._instruction`. The instruction
  must reach **state** (not `task`): the router sees only `state`, and its cache
  key is `(kind, state, options)`, so folding into `task` is an inert no-op.

**Honest limit on offline steering.** With the deterministic offline backend
(`static`/`TemplateLLM`), the loop takes option 0 regardless and the planner
only runs under `--mode full-llm|llm+decision` *and* when `len(options) > 1`. So
`goal <text>` folded into state biases a **live** LLM decider but does **not**
change the chosen action offline. `focus <surface>` reorders the pool and *does*
change behavior offline (it changes which surface is probed first). Tests assert
each truthfully: a `StubPlanner` under `full-llm` proves the instruction reaches
state and produces `plan` events; the offline-default test asserts `focus`
reordering, not instruction-driven routing.

### Per-command knowledge base

Each `goal` runs over a **fresh per-command `KnowledgeBase`**, whose accepted
findings are then `merge`d into the session KB. This avoids the dedupe trap: a
single shared KB would collapse a repeated `goal` over the same pool at the
`dedupe` stage (`promote_candidate` dedupes against `kb.accepted`), filing zero
new findings. Per-command KB → merge gives honest per-command results and an
accumulating session view.

## CLI

`_cmd_shell(args) -> int` builds config like `_cmd_run` (the
`if args.mode is not None` conditional so `mode=None` never clobbers
`AEGIS_MODE`), `local_only = not args.allow_egress`. Flags:
`--scope` (optional), `--authorized` (store_true), `--mode {full-llm,llm+decision,static}`
only (jev alone is invalid), `--decision-model`, `--allow-egress`, `--run-id`,
`--out`. No `main()` change — dispatch is generic via `args.func`.

## Testing (fully offline, CI-safe)

Self-contained (`tmp_path`/`monkeypatch`/`capsys` + local stubs; no `conftest`).
Every test `monkeypatch.delenv`s `AEGIS_LLM` / `AEGIS_LLM_API_BASE` /
`AEGIS_LLM_API_KEY` so `build_llm` never dials localhost and hangs CI. stdin is
driven via `monkeypatch.setattr("sys.stdin", io.StringIO("...\nexit\n"))`;
assertions read `capsys`. The `attempt` verb is tested with an injected
`FakeTransport` (the existing red-team test pattern) via a test-only transport
hook on the session.

Coverage targets the security invariants: unauthorized refusal, out-of-scope
refusal (no tool run), default-deny with no scope, `run`/`goal` zero-tool-run
and local-path rejection, verbatim target to `attempt`, type clamping, transcript
continuity (events.jsonl line count strictly grows across two commands),
unknown-command-stays-open, EOF-exits-0, `ScopeError`-returns-2-before-REPL, and
the `--mode` offline guard.

## Deferred (named follow-ups)

- **start()/step()/finalize() refactor** (architecture B): lift the loop state
  into a serializable `LoopState` and split `run()` so the shell can pause
  *within* a turn, `step N`, inject mid-turn, and resume. Higher Strix parity;
  gated behind a run-equivalence regression test so `test_engines.py` stays
  green. This milestone's `goal`/`focus` are the between-command stand-in.
- **First-class `user_message` event type** in the dashboard (`Agents.jsx`
  render case + `label()`), so a typed instruction renders distinctly in the UI
  rather than as a generic `message`.
