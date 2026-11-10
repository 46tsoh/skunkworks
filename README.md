# skunkworks — Aegis

**Aegis** is a unified, **local-only** security-analysis framework. It
reimplements, in original clean-room code, the decision-shaped patterns of two
open-source frameworks — **Strix** (dynamic security testing) and **RAPTOR**
(static/deep security research) — and runs them through one typed decision
layer, into one shared findings knowledge base, toward one unified report and
dashboard.

> **Defensive engineering, local-only.** Aegis builds tooling, orchestration,
> analysis and UI. Capabilities run only against the bundled sample target and
> user-authorized/owned targets — never third-party targets. Nothing is hosted
> or sent to a third-party service: decision backends are offline (`static`) or
> localhost (`basal`); the remote `jev` backend is refused unless egress is
> explicitly enabled.

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/aegis analyze                 # single pipeline on the sample corpus
.venv/bin/aegis run                     # BOTH engines over the sample target (unified report)
.venv/bin/aegis run --backend llm       # drive decisions with a standard local LLM
.venv/bin/aegis run --use-tools         # source candidates from the tool registry
.venv/bin/aegis tools                   # tool adapter inventory + availability
.venv/bin/aegis calibrate               # tune decision thresholds on a labeled corpus
.venv/bin/aegis run --out ./run         # also write report.json + decisions.jsonl
.venv/bin/pytest --cov=aegis            # 226 passing, ~96% coverage
```

## Tools

17 capability adapters sit behind one `Tool` interface (`aegis.tools`) — static
(`semgrep`, `codeql`, `sca`, `binary`, `fuzz`, `crash`, `forensics`) and dynamic
(`recon`, `web`, `dast`, `proxy`, `browser`, `shell`, `sandbox`, `poc`, `frida`,
`rr`). Binary-backed tools run in **local Docker containers** with `--network
none`, `--pull=never`, read-only mounts and resource caps — nothing installed on
the host, nothing hosted. Every adapter is **fixture-first**: it ships a recorded
output + the production parser, so the whole pipeline runs and the suite passes
with no images pulled. Pull images to run tools live: `./docker/pull-images.sh`
(see [`docker/README.md`](docker/README.md)).

## Models

Aegis uses models two ways — the same split Strix draws between its LLM and its
logic:

- A **standard generative LLM** (`aegis.llm`) — OpenAI-compatible, **local-first**
  (defaults to a localhost server like Ollama / llama.cpp / vLLM). Configure with
  `AEGIS_LLM`, `AEGIS_LLM_API_BASE`, `AEGIS_LLM_API_KEY`.
- The **typed decision layer** (`aegis.decision`) — `choose` / `score` / `boolean`
  with a probability, the triage/validate/dedup oracle.

A standard LLM can also *be* the decision backend (`--backend llm`). Everything
defaults to offline/localhost; the remote `jev` backend and non-localhost LLM
endpoints are refused unless egress is explicitly enabled.

## Package layout

- **`aegis/decision/`** — provider-agnostic typed-decision layer: one
  observable `DecisionRouter` over `choose` / `score` / `boolean` primitives,
  with Jev / basal-omni / LLM-judge / static backends and Strix/RAPTOR
  integration adapters.
- **`aegis/knowledge/`** — the unified `Candidate` / `Finding` / `Rejection`
  model (CVSS + CWE→OWASP) and the shared `KnowledgeBase` (rank / query / merge).
- **`aegis/config.py`** — thresholds, backend selection, env loading, and the
  `local_only` guard.
- **`aegis/analysis/`** — the combined pipeline: triage → hypothesis posterior →
  dedupe → staged exploitability validation → CVSS, every decision routed
  through the decision layer.
- **`aegis/cli.py`** — the `aegis` command.

`reference/jev/` and `poc/` remain as the original research artifacts; they are
now thin compatibility shims that re-export from `aegis` (single source of
truth), and their original test suites still pass through the shims.

## Documentation

- **Build status & milestones:** [`STATUS.md`](STATUS.md)
- **Architecture map (read first):** [`docs/continuation-architecture-map.md`](docs/continuation-architecture-map.md)
- **Decision-layer design rationale:** [`docs/jev-security-agent-integration.md`](docs/jev-security-agent-integration.md)
- **Subsystem specs (clean-room, grows per milestone):** `docs/specs/`
- **Upstream credits:** [`NOTICE`](NOTICE)

## Dashboard

A local **Vite + React + Tailwind** dashboard over the unified report — net-new
for RAPTOR, a big upgrade on Strix's TUI. It runs entirely locally (nothing
hosted). **One command** runs both engines over the sample target and opens it:

```bash
aegis dashboard                    # run both engines + open the dashboard (http://localhost:5173)
aegis dashboard --use-tools        # source candidates from the 17 tool adapters
aegis dashboard --no-serve         # just write ui/public/data, don't start the server
```

Or drive the pieces yourself:

```bash
aegis run --out ui/public/data     # produce a run for the dashboard
cd ui && npm install && npm run dev # http://localhost:5173
```

Views: Overview (KPIs, severity donut, OWASP, per-engine rollup), Findings
explorer (filter/sort + a detail drawer with the CVSS vector, the 8-stage
exploitability chain, evidence and the per-finding decision trail), Agent graph,
Hypotheses queue, the full **decision audit trail**, and the Tools catalog. See
[`ui/README.md`](ui/README.md).

Licensed under Apache-2.0.
