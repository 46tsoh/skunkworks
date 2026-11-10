# Aegis — continuation architecture map

The map the build follows: what each upstream does, the unified architecture we
build from it, and the UI plan. **Read this first** before picking up a
milestone. Design rationale for the decision layer is in
[`jev-security-agent-integration.md`](jev-security-agent-integration.md).

> **Operating constraint:** local-only. No hosting, no third-party infra. Every
> decision backend is offline or localhost; the UI is a local dev server.

## 1. What we are reverse-engineering

### Strix (Apache-2.0) — dynamic / black-box
Autonomous security-*testing* agent. Relevant architecture:
- **Graph of Agents** — recon / exploitation / post-exploitation specialists
  that share findings and run in parallel.
- **Toolbelt** — HTTP intercept proxy, browser automation, shell/command exec,
  a Python sandbox for writing+running validation code, recon/OSINT, SAST+DAST.
- **Findings knowledge base** — CVSS scoring + OWASP classification, LLM dedup,
  PoC generation to *prove* findings.
- **Extension points** — Skills (`SKILL.md`) and MCP servers.

### RAPTOR (MIT) — static / deep
Hypothesis-driven security-*research* framework. Relevant architecture:
- **Static** — Semgrep, CodeQL (+ SMT path-feasibility), SCA (deps,
  containers, SBOM).
- **Deep/dynamic** — binary analysis, fuzzing, crash analysis, frida-style
  dynamic instrumentation, web endpoint testing, oss-forensics (git history).
- **Hypothesis-driven audit engine** — evidence + coverage + posterior/verdict.
- **Staged `/validate`** — eight-stage exploitability chain.
- **Calibration** — specialist personas, a labeled corpus, calibration metrics,
  a mechanical `--no-llm` mode, per-run cost caps.

## 2. Unified Aegis architecture

```
                         ┌──────────────────────────────┐
                         │          aegis.cli            │
                         │   analyze · run · serve ...    │
                         └───────────────┬──────────────┘
                                         │
                         ┌───────────────▼──────────────┐
                         │      Orchestrator (M2)        │
                         │  drives two pluggable engines │
                         └───────┬───────────────┬──────┘
             ┌───────────────────▼──┐        ┌───▼──────────────────────┐
             │ DynamicEngine (M2)   │        │ StaticEngine (M2)        │
             │ Strix-style graph-of-│        │ RAPTOR-style hypothesis- │
             │ agents loop          │        │ driven audit loop        │
             └───────┬──────────────┘        └──────────────┬───────────┘
                     │        both call tools + decisions    │
          ┌──────────▼───────────┐            ┌──────────────▼──────────┐
          │  Tool interface (M3) │            │  Tool interface (M3)    │
          │ proxy·browser·shell· │            │ semgrep·codeql·sca·     │
          │ sandbox·recon·sast·  │            │ binary·fuzz·crash·frida·│
          │ dast·poc             │            │ web·forensics           │
          └──────────┬───────────┘            └──────────────┬──────────┘
                     └───────────────┬──────────────────────┘
                     ┌───────────────▼──────────────┐
                     │  aegis.decision.DecisionRouter │  ← one choke point
                     │  (triage·dedup·validate·score) │    thresholds+log+cache
                     └───────────────┬──────────────┘
                     ┌───────────────▼──────────────┐
                     │  aegis.knowledge.KnowledgeBase │  ← one shared store
                     │  Finding · Rejection · ranking │    CVSS · OWASP · dedup
                     └───────────────┬──────────────┘
                     ┌───────────────▼──────────────┐
                     │   Unified report + UI (M5/M6) │
                     └──────────────────────────────┘
```

**Built so far:**
- **M1:** `aegis.decision`, `aegis.knowledge`, `aegis.config`, `aegis.analysis`
  (the decision-stage pipeline), `aegis.cli analyze`.
- **M2:** `aegis.engines` (`Orchestrator` + `DynamicEngine` + `StaticEngine`
  over one shared router + KB, cross-engine dedup, `aegis run`) and `aegis.llm`
  (standard local-first LLM provider, also selectable as the `llm` decision
  backend). Specs in `docs/specs/`.

**Model seams.** Aegis uses models two ways, like Strix split from its decision
logic: a **standard generative LLM** (`aegis.llm`, OpenAI-compatible, local-first
— "writes & plans") and the **typed decision layer** (`aegis.decision` — "decides").
A standard LLM can also *be* the decision backend (`--backend llm`) via the
LLM-judge bridge. Both default to offline/localhost; remote egress is gated by
`AegisConfig.local_only`.

**Key unifying ideas:**
1. **One decision router.** Every branch either engine takes (triage, dedup,
   exploitability gate, priority score) is a typed decision through
   `DecisionRouter` — so it is thresholded, cached, logged, and replayable.
2. **One knowledge base.** Both engines write `Finding`s into one
   `KnowledgeBase`; dedup and ranking are cross-engine, so the final report is
   unified, not two reports stapled together.
3. **One Tool interface.** Every capability (dynamic or static) is a `Tool`
   with a uniform `run(target, ...) -> ToolResult`; the orchestrator and both
   engines are tool-agnostic. External binaries are adapters behind this
   interface; when a binary can't be hosted locally it is recorded in
   `STATUS.md` and routed around, but the adapter + tests still exist.

## 3. Engine responsibilities (M2 specs to write)

- **DynamicEngine** — maintains an agent graph (roles, shared blackboard,
  parallel steps), drives tools against an *authorized/sample* target, emits
  `Candidate`s, generates PoCs to prove accepted findings on that target.
- **StaticEngine** — maintains a hypothesis queue (priority-scored), gathers
  evidence via static tools, tracks coverage, runs the staged `/validate`
  chain, emits `Candidate`s with evidence and a posterior.

Both share the router + KB and are independently runnable and testable with the
offline `static` backend.

## 4. Tool interface (M3 spec to write)

`Tool`: `name`, `kind` (`dynamic`/`static`), `requires_binary`, `available()`,
`run(target, **opts) -> ToolResult{candidates, raw, artifacts, errors}`. Offline
adapters (parse fixture output, run on the bundled sample) ship first so the
pipeline is testable without binaries; binary-backed adapters detect the binary
and degrade to a clear "unavailable" result when absent.

## 5. Unified UI (M5 plan) — improves on both originals

Stack: **Vite + React + Tailwind**, served on a local dev server (no hosting).
Net-new for RAPTOR; a large upgrade over Strix's TUI/`strix view`. Reads the
unified `report.json` (and, later, a live run stream).

- **Live run view** — orchestrator + engine progress, decisions ticking through
  the router (kind, probability, threshold, backend).
- **Findings explorer** — filter/sort by severity, CVSS, OWASP, engine,
  exploitable; finding detail with evidence and the validation trace.
- **Agent graph** — the dynamic engine's graph-of-agents, live.
- **Static-audit + hypothesis view** — hypotheses, posteriors, coverage, the
  `/validate` stage chain per candidate.
- **Unified report** — one deduped, ranked list across both engines, exportable.
- **QoL the originals lack** — decision replay/audit trail, threshold tuning
  with instant re-rank, calibration metrics.

Finish bar: `/impeccable` audit → critique → polish → typeset → animate;
`emil-design-eng` for motion; `design-taste-frontend` for the overview/landing.

## 6. Interop command (M6)

`aegis run --target <sample>` runs both engines over the bundled sample,
merges into one `KnowledgeBase`, dedupes cross-engine, writes one unified
`report.json`, and opens the dashboard — all local.
