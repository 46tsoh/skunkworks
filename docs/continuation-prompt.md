# Continuation kickoff prompt — unified Strix + RAPTOR framework (AEGIS)

Paste the block below into a fresh Claude Code CLI session **in your local clone of
`skunkworks`**, with the three design skills installed. Launch it with the `/loop`
skill (no interval → self-paced, resumes the same run until the finish condition is
met). The block is also the authoritative spec; a detailed reverse-engineering map and
target architecture live in [`continuation-architecture-map.md`](continuation-architecture-map.md).

> Note on "ultracode": it opts this harness into multi-agent **workflow** orchestration
> where available; `ultrathink` is the always-real max-reasoning token. The prompt
> starts with both plus `/loop`, so it works whether or not your build exposes an
> "ultracode" mode — don't hunt for a mode that isn't there.

```text
ultracode ultrathink

MISSION
Build a unified, open-source security-analysis framework (codename AEGIS) in this repo
(skunkworks) that REVERSE-ENGINEERS and reimplements the FULL capabilities and
architecture of BOTH Strix (usestrix/strix, Apache-2.0) and RAPTOR (gadievron/raptor,
MIT) — every capability, nothing left as an empty stub — makes them interoperate under
ONE orchestrator with ONE shared knowledge base and ONE decision layer, and presents
BOTH through ONE modern unified web UI that IMPROVES on what either framework offers.

BASELINE (already on `main`, build on it — do NOT rebuild):
  - reference/jev/  — provider-agnostic typed-decision layer: DecisionRouter
    (thresholds, caching, JSONL log, record_outcome calibration) + backends
    BasalOmni/Jev/LLMJudge/Static + integrations/{strix_decisions,raptor_gates}.py.
  - poc/            — combined pipeline (triage → hypothesis posterior → dedup →
    staged exploitability validation → CVSS) routed through the decision layer.
  - data/sample_findings.json — the bundled benign sample target.
  - docs/continuation-architecture-map.md — READ FIRST: the reverse-engineering map of
    both frameworks + the AEGIS target architecture + the UI plan.
  - docs/jev-security-agent-integration.md — design rationale.

TOOLCHAIN REALITY (verify against this, don't assume):
  - Python 3.13, Node 22. The existing code is deliberately STDLIB-ONLY, zero third-
    party deps (CVSS is reimplemented to avoid one). Keep AEGIS core stdlib-first.
  - pytest is NOT installed — tests are stdlib `unittest`. semgrep/codeql/afl++/frida
    etc. are NOT installed and outbound installs go through a restricted proxy.
  - Therefore: isolate heavy deps (scanners, React/Vite) into optional subtrees so the
    CORE test suite always runs offline. Scanner adapters MUST degrade gracefully when
    the binary is absent and MUST be verifiable offline against SAMPLE SARIF/finding
    fixtures checked into the repo. A capability is "done" when its adapter + parsing +
    integration + fixture-based unittest pass — never leave a capability as a bare TODO.

REVERSE-ENGINEER, DO NOT COPY (hard rules):
  - The upstream source is NOT in this repo. Clone upstreams READ-ONLY into
    reference/_upstream/ (gitignore it) for behavioral study only. Never import from
    them, paste from them, vendor their files, or hallucinate their internals.
  - Spec-first / clean-room: before a subsystem, write docs/specs/<name>.md describing —
    in YOUR words — its behavior, inputs/outputs, data model, algorithm, interfaces.
    Then implement from your spec with the upstream source CLOSED. Original code only.
  - Per-milestone self-check: no new file is a line-for-line copy (spot-diff vs
    reference/_upstream). Licenses: Strix Apache-2.0, RAPTOR MIT — add a NOTICE file
    crediting both and record provenance in docs/. End every commit with the required
    attribution lines and every PR body with the Generated-with-Claude-Code block.

FULL CAPABILITY PARITY — implement ALL, each with offline fixture tests:
  Dynamic (Strix): HTTP intercept proxy; browser automation; shell/exec; python
    sandbox for validation code; recon/OSINT; SAST+DAST; graph-of-agents multi-agent
    orchestration; findings KB with CVSS+OWASP; LLM dedup; MCP + SKILL.md extension
    points; PoC-to-prove-a-finding (on sample/authorized targets only).
  Static (RAPTOR): Semgrep; CodeQL (+SMT path-feasibility); SCA (deps/containers/SBOM);
    binary analysis; fuzzing; crash analysis; instrumentation (frida-style); web
    endpoint testing; oss-forensics; hypothesis-driven audit engine (evidence +
    coverage + Bayesian posterior/verdict); the staged /validate exploitability chain
    (Stage 0/A–F with capability ceiling); specialist personas; labeled corpus +
    calibration metrics.

INVARIANTS (never violate):
  - GOLDEN REGRESSION: `python -m poc.cli` currently yields EXACTLY — candidates=7,
    accepted=4, rejected=3, decisions=47, cache hits 0; accepted ranked F1(Crit 9.8,
    EXPLOITABLE), F7(Crit 9.3, EXPLOITABLE), F5(Med 6.5, EXPLOITABLE), F6(Low 3.6, info
    stopped@2); rejected F2(dedupe dup of F1), F3(triage FP), F4(hypothesis 0.35<0.5).
    M1 must wrap this as an automated test; every later milestone must keep it exact.
  - MECHANICAL FLOORS ARE INVIOLABLE / the DecisionRouter is ADVISORY only:
    deterministic CVSS, the verdict/downgrade ladder, the Stage-E capability ceiling,
    provenance stamps, fail-OPEN dedupe (any error ⇒ not a duplicate), fail-CLOSED
    budget — these always override the router and must never be laundered through it.

SCOPE / GUARDRAILS (hard boundary, DEFENSIVE security engineering):
  - Reimplement orchestration / decision-routing / analysis / reporting / UI PATTERNS
    in original code, over sample/benign in-repo data and explicitly user-authorized
    targets ONLY. The /validate + exploitability reasoning operate over FINDING TEXT
    only (as poc/validate.py does — reaches no target).
  - Do NOT build new attack capability, bundle weaponized exploits, or scan/reach real
    third-party hosts. The ONLY hard stop is a step that crosses into real-target
    offense or weaponization — then stop and note it. Nothing else is a reason to stop.

OPERATING MODE — RUN UNTIL FINISHED, don't idle-stop:
  - Use ultracode/workflows per phase (understand → spec → implement → review) and the
    /loop skill to resume the SAME run across cycles. Do NOT ask permission to continue
    and do NOT declare done early. If a milestone blocks, work around it or switch to
    other independent milestone work and come back — keep making progress.
  - Keep STATUS.md at repo root (milestones, done/in-progress/blocked, next action);
    update every cycle; use it to avoid repeating work.
  - GOVERNORS (fail CLOSED so an unattended/local-model loop can't run away): enforce a
    max wall-clock / max loop-cycle cap and RAPTOR-style max_seconds/calls/tokens plus
    Strix budget hooks (warn/pause/stop/reserve). Auto-resume from the last green
    milestone on crash; halt cleanly on EITHER a governor cap OR the finish condition.
  - One milestone at a time, independently shippable: branch off latest origin/main,
    tests green, draft PR, merge when green, then next. Don't rewrite working code for
    taste; keep each change scoped.

MILESTONES (refine against the architecture map):
  1. aegis/ core: unified Finding/Hypothesis/Evidence/Coverage/Report model (superset
     of poc/models.py), the shared DecisionRouter, config/env, CLI. Freeze the golden
     regression as a test.
  2. aegis/orchestrator: Strix-style AgentCoordinator (graph state, mailboxes, budget
     pause/resume/stop, resumable snapshots) + the perpetual run-until-finished driver,
     running two pluggable engines that share one KB + one router. Spec each engine first.
  3. aegis/engines + aegis/adapters: dynamic engine (graph-of-agents, browser/proxy/
     shell/sandbox) and static engine (gaps → hypothesis mapping → staged /validate +
     Bayesian posterior). All scanner adapters implemented with offline fixture tests.
  4. Analysis parity through the decision layer; calibrate thresholds on a labeled
     sample corpus (aegis/decision/calibration.py + thresholds.yaml).
  5. aegis/server + ui/: ONE web dashboard over BOTH engines (React 19 + Vite 6 +
     Tailwind v4, React Flow for the agent graph), live via a JSON+WebSocket contract
     off the KB (not 500ms polling). Then make it impeccable: /impeccable audit →
     critique → polish → typeset → animate; emil-design-eng animate/choreograph for
     motion. CAP the polish loop — fix only P0/P1, 2–3 passes per screen, stop when the
     detector exits 0 at 390/768/1024/1440px with no horizontal scroll. Use
     design-taste-frontend ONLY for a separate landing page, NOT the dashboard.
  6. End-to-end interop: one command runs BOTH engines over the sample target → one
     unified, deduped, ranked report + the dashboard.
  7. Docs, tests, CI: README, architecture doc, >80% core coverage (unittest), a CI
     workflow running the offline suites.

FINISH CONDITION: all 7 milestones verified green — BOTH `python -m unittest discover
-s reference/jev/tests` and `-s poc/tests` pass, the golden regression reproduces
exactly, the aegis core suite passes offline, the UI /impeccable detector exits 0 — AND
the working tree is committed with the final PR merged. Verify each milestone with a
concrete shell command whose exit code is the gate; reproduce before claiming a fix;
never disable a test to go green.
```
