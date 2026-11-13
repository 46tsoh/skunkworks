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

**Active DAST is on the payloads side of this line.** ZAP's active scan sends
real attack payloads, so it is *not* autonomous: the dast phase defaults to the
passive baseline. A configured planner may *request* active depth for the goal,
but attack traffic runs only when the operator set `--active-dast` (default off),
mirroring `scan --active` and `--exploit` — the human beat, set once before the
run. See *DAST depth* below.

## Flow (`drive_agent`)

1. **Scan** — for each phase in `recon, web, dast`:
   - When a real generative planner is configured (`--mode full-llm|llm+decision`
     with `AEGIS_LLM*` pointed at a local model), the planner may choose an
     ordered **subset** of these phases adapted to the goal; the choice is
     **clamped to this fixed set** (`clamp_phases`) before it is used — it can
     prune or reorder, never add a phase or change the target. Offline /
     `TemplateLLM` / `static` run all three in order, exactly as before.
   - **DAST depth** (the one goal-adaptive *within-phase* axis): for the dast
     phase, when a real planner is configured **and** `--active-dast` was passed,
     `plan_depth()` proposes passive/active for the goal and `clamp_depth()`
     enforces the operator ceiling; a triple-gate (operator-permitted **and**
     planner-selected **and** `phase == "dast"`) decides the ZAP scan. Offline /
     `TemplateLLM` / `static`, and any planner failure, run the passive baseline.
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
- **Phase selection is clamped** to `DEFAULT_PHASES`, exactly as the weakness
  type is clamped to the technique set. The planner receives only the goal and
  the allowed phase names (never `scope`/`authorized`/`target`); `clamp_phases`
  draws every chosen phase *from* the trusted set, so a planned step can prune
  or reorder but never add a phase, change `--target`, or flip authorization.
  Every selected phase still passes `authorize()` on its exact per-phase target
  before any traffic.
- **DAST depth is clamped** to the operator ceiling, paralleling phase
  selection. The planner receives only the goal and a passive/active description
  (never `scope`/`authorized`/`active_allowed`/`target`); `clamp_depth` draws
  from `{active, passive}` and returns `active` only when the operator passed
  `--active-dast` **and** the planner chose it. So the planner can request
  passive or active but can **never** enable attack traffic the operator did not
  permit — with the flag off, the result is constant passive whatever the
  planner says. Model-authored scanner args/commands stay out of scope (`argv`
  is code-authored; the only planner-influenced knob is this clamped bool).

## CLI contract

```
aegis agent "<goal>" --target <host|url> [--scope F] [--authorized] [--exploit]
                     [--active-dast] [--mode M] [--backend B] [--allow-egress]
                     [--out DIR] [--json] [--run-id ID]
```

- **Exit codes** (mirroring `aegis exploit`): `2` refusal — `--exploit` or
  `--active-dast` without `--authorized`/`--scope`, a scope/`config` error —
  printed to stderr **before any traffic**; `1` operational failure (a scanner
  phase errored → `degraded`) **or** an `--exploit` run where leads existed but
  none confirmed; `0` clean. (`--active-dast` does not change the `0`/`1`
  contract — a permitted active run that finds nothing is still `0`.)
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
- **Phase selection is goal-adaptive only with a real model.** With a configured
  local model the planner chooses an ordered subset of `recon → web → dast` for
  the goal (clamped to that set). In `static` mode (and in `full-llm`/
  `llm+decision` with no `AEGIS_LLM*`, which falls back to `TemplateLLM`) the
  chain is the full fixed sequence, as before. A planned run may be **narrower**
  than a full chain (e.g. pruning `recon` changes which findings exist) —
  intended adaptivity, not a safety relaxation.
- **Within-phase tool *selection* is 1:1 today** (a seam, not a capability):
  each live phase maps to exactly one network adapter (recon→nmap, web→nuclei,
  dast→ZAP); proxy/browser run `--network none` over saved pages and are not
  interchangeable live-target scanners, so there is nothing to select among. The
  one real within-phase axis delivered is **DAST depth** (passive/active),
  planner-requested and operator-gated. Free-form model-authored scanner
  args/commands, and multi-tool-per-phase selection, stay deferred.
- **`scan` container egress gates only the seed** (inherited from `aegis scan`):
  a scanner that spiders paths/ports or follows redirects is not re-checked per
  request. Scope `agent`/`scan` engagements at host granularity. `attempt`
  re-checks every request.
- **Exit code reflects stage-1 confirmation only**, not a full severity verdict;
  CI that wants richer gating reads `report.json` (`accepted[]`,
  `summary.severity_counts`, `metrics.agent`).

## Deferred (named follow-ups)

- Within-phase **tool selection** (1:1 today — a seam, no alternative live tools
  per phase) and free-form model-authored scanner args/commands. Phase
  *selection* is done (milestone 24); DAST *depth* is now goal-adaptive
  (milestone 25).
- `start()/step()/finalize()` engine refactor for within-turn pause/resume
  (shared with the shell's deferred item).
- Per-request scope-enforcing egress proxy for scanner containers.
