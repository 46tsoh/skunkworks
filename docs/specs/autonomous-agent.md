# Autonomous agent — `aegis agent`

*Aegis milestone 23. Clean-room: a Strix-style autonomous, headless agent that
drives a whole engagement from a goal. Local-only. Builds on the interactive
shell (milestone 22, `docs/specs/interactive-shell.md`).*

## Why

`aegis shell` is operator-driven — you issue each verb. Strix's defining mode is
the opposite: you give one goal and the agent drives itself. This milestone adds
that: `aegis agent "<goal>" --target <t>` chains the live scanners, triages
every finding, and (on explicit go-ahead) confirms exploits — headless, with a
real exit code and a machine-readable result, and also from inside the shell.

## Autonomy envelope — scan, then confirm-to-exploit

The agent is autonomous for **reconnaissance and triage**, and deliberately
**not** autonomous for sending exploit payloads. It chains recon → web → dast
and triages into one knowledge base on its own; then it **stops at the
confirm-to-exploit gate**. Stage-1 exploit-confirmation probes fire only on an
explicit go-ahead:

- headless: the `--exploit` flag;
- interactive (`aegis shell`): a typed `go` at the prompt.

This is the chosen safety default: unattended autonomy up to the point of
sending attack traffic, a human beat before payloads.

## Tool selection (milestone 24)

The scanner order is no longer fixed. When a local model is wired, the **LLM
selects the next scanner each step** from the hard allowlist, conditioned on what
has been found so far — the Strix trait. The decision is a `plan → commit` split
exactly like the dynamic engine: `plan_tool_selection` has the model **propose**
an option; `DecisionRouter.choose` **commits** it (logged, cached, thresholded).

**The allowlist is structural, in three independent layers** — no single mistake
or hostile model/finding can reach a code-execution adapter:

1. **Names never cross the boundary.** `ALLOWLIST = frozenset({recon, web, dast})`
   is a module constant. Each step's options are *constructed* from
   `ALLOWLIST ∩ caller-phases` (`[f"run:{t}"] + ["stop"]`). The loop **never**
   calls `registry.available(ToolKind.DYNAMIC)` or builds a `RegistryProbe`, so
   `shell`/`sandbox`/`poc`/`frida`/`proxy`/`browser` names are not in the universe
   the planner or router ever sees. The planner returns an **index**, not a name.
2. **Out-of-range is a fallback, not a clamp.** `plan_tool_selection` returns
   `None` on a bad/hostile/out-of-range/non-JSON reply (the fixed-order option 0
   is used, tagged `fallback`); it never clamps a wild index onto a real option.
3. **The runner re-checks.** `_run_scanner` rejects any `phase ∉ ALLOWLIST`
   (−O-safe, not an `assert`) and still requires `isinstance(DockerBackedTool)` +
   `allows_network` — which only recon/web/dast set.

`phases` is **narrow-only**: `("shell",)` → empty allow → nothing runs. The
planner's **state carries only counts + tool names + the goal** — never raw
finding text or the authorize reason — so a hostile scan finding cannot steer the
agent to a new target or tool. Scope and the `authorized` flag never enter the
planner. Every selected scanner is still `authorize()`-gated on the exact
per-phase bytes before any traffic (unchanged), and a picked tool is removed from
the remaining set **before** the gate/run so a refusal can't be replayed; the
loop is bounded by `--max-tool-steps` (default: the allowlist size).

**Honest degradation (gap #2).** `drive_agent` self-builds the selection planner
from config: a real provider **and** `mode != static`. So a wired local model
drives selection at the **default** (`--mode` unset, loopback under
`local_only`); `--mode static` stays fully offline; and an unconfigured or dead
model degrades to the fixed `recon → web → dast` order and **says so**
(`planner: fixed …` / `planner unreachable on N step(s)`), never presenting a
scripted run as model-driven. Fixed-mode selection is byte-for-byte the old order.

## Flow (`drive_agent`)

1. **Scan** — the LLM (or fixed order) selects each scanner from the allowlist;
   for the chosen phase:
   - derive the per-phase target form (`phase_target`): a **bare host** for
     `recon` (nmap), a **URL** for `web`/`dast` (nuclei/ZAP);
   - `authorize(scope, authorized, phase_target)` on the **exact bytes the tool
     will receive** — refuse (emit `scope_refused`, record, skip) if not
     authorized or out of scope; also refuse a target that resolves to a local
     path (as `scan` does);
   - run the Docker scanner (`--network=bridge`), feed its candidates through
     the dynamic triage loop (`run_narration`) into the session KB, deduped by
     `(title, component)` (`fold_findings`).
2. **Triage** — for each confirmed, exploitable finding, `attemptable()` derives
   `(type, target, param)`: the technique for the finding's CWE (or its title
   keyword) via `technique_for`; the `component`, which must be an http(s) URL;
   and `param` from structured `metadata['param']` (persisted by the dast
   adapter) or the URL query string. Leads that lack a technique, a URL, or a
   param are **skipped and counted** (never silently dropped).
3. **Confirm-to-exploit gate** — if there are no attemptable leads, stop. Else,
   unless `--exploit` (or a typed `go`) says proceed, stop and report the leads.
4. **Exploit** — for each lead, `authorize()` again on the lead target, then
   `RedTeamEngine.attempt(type, target, param)` (which re-checks scope and
   routes through its scope-gated transport). Collect verified results.

**Unauthorized path:** with `authorized=False` the agent runs **no live phase**;
it narrates offline over the bundled sample pool (clearly labelled) and can never
exploit. This keeps the whole flow demonstrable and testable with no Docker/network.

## Safety (carried from the shell, unchanged)

- **Every live action is gated** by the same `authorize()` the shell uses —
  default-deny, on the exact per-phase / per-lead target bytes.
- **The agent loop never receives `scope` or `authorized`.** `drive_agent` holds
  them; the dynamic loop sees only the candidate pool and the goal (folded into
  state). A planned step cannot widen its own authority.
- **`--exploit` requires `--scope`** (refused otherwise, before any traffic).
  With no `--scope`, the session gets a default-deny `EngagementScope()` and every
  live phase refuses.
- **Weakness type is clamped** to the technique set; the target passes verbatim
  to `authorize()`/`attempt()`; output is sanitized at the terminal.

## CLI contract

```
aegis agent "<goal>" --target <host|url> [--scope F] [--authorized] [--exploit]
                     [--mode M] [--backend B] [--allow-egress]
                     [--out DIR] [--json] [--run-id ID]
```

- **Exit codes** (mirroring `aegis exploit`): `2` refusal — `--exploit` without
  `--scope`, a scope/`config` error — printed to stderr **before any traffic**;
  `1` operational failure (a scanner phase errored → `degraded`) **or** an
  `--exploit` run where leads existed but none confirmed; `0` clean.
- **`--out DIR`** writes `report.json` (the same shape `aegis run` writes, so the
  dashboard renders it), plus `events.jsonl` and `decisions.jsonl`. The agent
  summary is under `metrics.agent`.
- **`--json`** prints the final result object as the **only** line on stdout; the
  live transcript is routed to **stderr**, so a headless caller parses stdout
  cleanly.

## Interactive (`aegis shell`)

The shell gains an `agent <target> [goal...]` verb — a live verb gated at the
dispatcher. It runs the same `drive_agent`, streams, and at the
confirm-to-exploit gate reads the **next REPL line** as the go/no-go answer
(`go` proceeds). So the autonomous agent is drivable both headless and from the
Claude-like shell.

## Honest limits

- **Offline reasoning is templated, not a real agent brain.** In the default
  `static` mode (and in `full-llm`/`llm+decision` with no `AEGIS_LLM*`
  configured, which falls back to `TemplateLLM`), the dynamic loop takes the
  deterministic option and the plan is scripted — the transcript *looks* agentic
  but is not model-driven. Point `AEGIS_LLM*` at a local model (loopback under
  `local_only`) for genuine planning/rationale.
- **Tool selection is LLM-driven only with a wired model.** With no
  `AEGIS_LLM*` (or `--mode static`), the order is the fixed `recon → web → dast`
  and the goal only tilts triage — disclosed at runtime. The *set* of tools is
  the three network scanners; the agent does not select deeper tools (deliberate
  — see gap #3 below).
- **Exploitation stays stage-1 confirm only** (gap #3), deliberately bounded for
  a defensive, local-only tool: the agent never writes/runs arbitrary PoC code,
  and the selector cannot choose code-execution tools. This is a design choice,
  not a missing feature.
- **`scan` container egress gates only the seed** (inherited from `aegis scan`):
  a scanner that spiders paths/ports or follows redirects is not re-checked per
  request. Scope `agent`/`scan` engagements at host granularity. `attempt`
  re-checks every request.
- **Exit code reflects stage-1 confirmation only**, not a full severity verdict;
  CI that wants richer gating reads `report.json` (`accepted[]`,
  `summary.severity_counts`, `metrics.agent`).

## Deferred (named follow-ups)

- **Widening the selectable tool set beyond the three network scanners** —
  deliberately *not* done: letting the agent pick code-execution adapters
  (shell/sandbox/poc) is exactly the ungated hazard this milestone designed
  against. Any such change must keep the allowlist/gate invariants and the
  `allowlist-cannot-escape` test as the tripwire.
- `start()/step()/finalize()` engine refactor for within-turn pause/resume
  (shared with the shell's deferred item).
- Per-request scope-enforcing egress proxy for scanner containers.
