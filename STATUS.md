# Aegis — build status

Living tracker for the unified security-analysis framework. Updated every
iteration. **Operating constraint: local-only** — nothing is hosted or sent to
a third-party service; all decision backends are offline (`static`) or
localhost (`basal`), and the UI runs on a local dev server.

## Honest scope note

Full, un-stubbed parity with *both* Strix and RAPTOR (HTTP proxy, browser
automation, sandbox, recon, SAST+DAST, semgrep, CodeQL+SMT, SCA, binary
analysis, fuzzing, frida, ghidra, a polished React dashboard, CI, >80% core
coverage) is a large, multi-session effort. This repo makes real, tested,
milestone-by-milestone progress. A capability is only marked **done** when it
is implemented *and* tested; anything partial is **in-progress** with the next
action named. Nothing here is faked to look finished.

## Milestones

| # | Milestone | State | Next action |
|---|-----------|-------|-------------|
| 1 | Core `aegis/` package (unified Finding/KnowledgeBase, DecisionRouter, config/env, CLI, tests) | **done** (merged #3) | — |
| 2 | Orchestration core: one orchestrator, two pluggable engines (dynamic graph-of-agents + static hypothesis loop), shared KB + router | **done** | — (specs in `docs/specs/`, `aegis.engines`, `aegis run`) |
| 3 | Tool/scanner adapters behind a common `Tool` interface (dynamic + static capabilities) | **not started** | spec written (`docs/specs/tool-interface.md`); implement `aegis.tools` registry + offline fixture adapters first (semgrep, SCA, recon), then binary adapters |
| 4 | Analysis parity through the decision layer (exploitability chain + hypothesis posterior + triage/dedup/CVSS), calibrated on a labeled corpus | **partial** | pipeline + both engines route through the decision layer (M1/M2); add labeled corpus + calibration metrics tool |
| 5 | Unified UI (Vite + React + Tailwind) over both engines | **not started** | scaffold after M2 exposes a run/report API |
| 6 | End-to-end interop: one command runs both engines over the sample target → one unified deduped report + dashboard | **not started** | depends on M2, M5 |
| 7 | Docs, tests, CI (README, architecture doc, >80% core coverage, CI) | **partial** | arch map + README done; add GitHub Actions CI (user-approved) running pytest + UI build on every PR |

## Milestone 2 — done

- Clean-room specs authored first (upstream closed during implementation):
  `docs/specs/{orchestrator,dynamic-engine,static-engine,tool-interface}.md`.
- `aegis.engines` — `Orchestrator` driving two pluggable engines that share one
  `DecisionRouter` + one `KnowledgeBase`:
  - `DynamicEngine` (Strix-style graph-of-agents loop; routing via
    `DecisionRouter.choose`, triage via `.gate`, promotion via the shared stages),
  - `StaticEngine` (RAPTOR-style hypothesis queue; priority via
    `DecisionRouter.score`, then triage → posterior → dedupe → validate → score).
- Cross-engine dedup through the same `dedupe.same_vuln` decision; one unified,
  ranked report. `parallel` and serial runs yield identical results.
- **`aegis.llm`** — standard generative LLM provider (OpenAI-compatible,
  local-first, `AEGIS_LLM*` env), usable as the `llm` **decision backend**
  (Strix-style "standard model decides") and for generative summaries; offline
  `TemplateLLM` fallback so no server is required.
- Bundled sample target (`data/sample_target/`) with a deliberate cross-engine
  duplicate; `aegis run` executes both engines over it.
- Tests: **95 passing**, **95%** coverage on `aegis`.

### Verify milestone 2
```bash
.venv/bin/pytest --cov=aegis            # 95 passed, ~95% coverage
.venv/bin/aegis run --serial            # both engines over the sample target
.venv/bin/aegis run --backend llm       # standard-model decision path (offline)
```

## Milestone 1 — done (merged #3)

- `aegis/` installable package (`pyproject.toml`, `aegis` console script).
- `aegis.decision` — typed decision layer (router + client + Jev/basal/LLM-judge/static backends + Strix/RAPTOR integration adapters), promoted from `reference/jev`.
- `aegis.knowledge` — unified `Candidate` / `Finding` / `Rejection` / `Severity` model with CWE→OWASP classification, and a shared `KnowledgeBase` (rank/query/merge/serialize).
- `aegis.config.AegisConfig` — thresholds, backend selection, env loading, and the `local_only` guard that refuses the remote Jev backend by default.
- `aegis.analysis` — the combined pipeline (triage → hypothesis → dedupe → validate → CVSS) populating a shared `KnowledgeBase`.
- `aegis.cli` — `aegis analyze` (writes `report.json` + `decisions.jsonl`).
- `reference/jev` and `poc` are now thin compatibility shims re-exporting from `aegis` (single source of truth); their original test suites pass unchanged through the shims, proving the promotion preserved behavior.
- Tests: **69 passing**, **93%** coverage on `aegis`.

### Verify milestone 1
```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest --cov=aegis         # 69 passed, ~93% coverage
.venv/bin/aegis analyze              # runs the pipeline on the sample corpus
```

## Reverse-engineering discipline (for M2+)

- Upstreams will be cloned **read-only** into `reference/_upstream/` (gitignored); read freely, never import/paste/vendor.
- Spec-first: write `docs/specs/<name>.md` in our own words before implementing each subsystem, then implement with upstream source closed.
- `NOTICE` credits derived patterns; no file is a line-for-line copy.

## Blocked / decisions pending

- **M3 external binaries** (semgrep, CodeQL, afl++, frida, rr, ghidra): installing these system-wide on the user's machine is a consequential, hard-to-reverse action — to be confirmed with the user when M3 starts. Offline-capable adapters and their tests will be built regardless; binaries that can't be hosted locally get recorded here and routed around.
