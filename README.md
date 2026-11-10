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
.venv/bin/aegis run --mode full-llm --allow-egress      # one LLM plans AND decides
.venv/bin/aegis run --mode llm+decision --allow-egress  # LLM plans/writes, decision model (Jev) decides
.venv/bin/aegis run --use-tools         # agent selects the real tool adapters
.venv/bin/aegis tools                   # tool adapter inventory + availability
.venv/bin/aegis calibrate               # tune decision thresholds on a labeled corpus
.venv/bin/aegis dashboard               # run both engines + open the live dashboard
.venv/bin/pytest --cov=aegis            # 258 passing, ~95% coverage
```

### Scanning an authorized target

`aegis scan` runs a real scanner live against an external target and drives its
findings through the full agent loop (reasoning transcript, decisions, spawned
subagents) — viewable in the dashboard. It is **gated behind `--authorized`** and
only ever runs the network scanners (recon/web/dast), never local-execution
tools. Use it on targets you **own, public test ranges, or competition/CTF
targets you are permitted to test** — never arbitrary third parties.

```bash
./docker/pull-images.sh                 # pull the scanner images once (local, dockerized)

# nmap the canonical authorized test host, through the agent loop, into the UI:
aegis scan --target scanme.nmap.org --tool recon --authorized --out ui/public/data
aegis dashboard                         # read the agent transcript over the real target

# drive it with a model (Claude plans, Jev decides) for richer reasoning:
aegis scan --target scanme.nmap.org --tool recon --authorized \
           --mode llm+decision --allow-egress --out ui/public/data

# web scan (nuclei templates) and DAST (OWASP ZAP) against an authorized web app:
aegis scan --target http://demo.testfire.net --tool web  --authorized --out ui/public/data
aegis scan --target http://demo.testfire.net --tool dast --authorized --out ui/public/data           # passive baseline (safe, fast)
aegis scan --target http://demo.testfire.net --tool dast --authorized --active --out ui/public/data   # ACTIVE scan — sends real attack payloads
```

The `dast` tool defaults to a **passive baseline** (spider + passive rules, no
attack traffic). `--active` runs ZAP's **active scanner**, which sends real
attack payloads (SQLi, XSS, traversal…) to every parameter — intrusive and slow,
so it is opt-in and, like every scan, still gated behind `--authorized`.

### RAPTOR static tools on real code (offline, local)

The deep static analyzers run against a local code tree with `--network none`
(their offline data is provisioned once by `./docker/pull-images.sh`):

```bash
# SCA (Trivy), SAST (Semgrep) and dataflow (CodeQL) over a local repo:
aegis run --target /path/to/repo --use-tools --out ui/public/data
```

- **sca** (Trivy) — vulnerable/outdated dependencies; vuln DB in a cached volume.
- **semgrep** — pattern SAST across 16 languages; OSS `semgrep-rules` in a volume.
- **codeql** — source→sink **dataflow/taint** (injection, SSRF, open-redirect);
  query packs ship in the image. Builds a DB then analyzes (slow; far slower if
  the image is emulated on a non-amd64 host).

### Autonomous red-team (scope-gated) — `aegis exploit`

Aegis's second use case (OSAI / CTF): the engine *acts* on a weakness to produce
proof. Stage 1 chains **confirm → verify → stop** — a few non-destructive marker
probes for reflected XSS, boolean/error SQL injection, or open redirect, verified
by an observable oracle. No shell, persistence, or lateral movement (later,
scope-gated stages). See [`docs/specs/red-team-engine.md`](docs/specs/red-team-engine.md).

Two gates are required: `--authorized` **and** a `--scope` engagement file that
every action is checked against (default-deny; out-of-scope targets are refused
before any request is sent).

```bash
# engagement.scope.json lists exactly what may be touched (see data/examples/)
aegis exploit --target http://demo.testfire.net/search.jsp --param query \
              --type xss --scope engagement.scope.json --authorized
#   CONFIRMED  [CWE-79]  1 request(s)
#   proof: reflected XSS confirmed on 'query': payload echoed unencoded into HTML
```

Scan only targets you own, public test ranges, or competition/CTF targets you are
permitted to test — never arbitrary third parties.

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

Aegis splits a run the way Strix does — *the LLM writes & plans, the decision
model decides, code acts*:

- A **standard generative LLM** (`aegis.llm`) — OpenAI-compatible, **local-first**
  (Ollama / llama.cpp / vLLM, or a LiteLLM gateway). It plans the next action and
  writes the finding rationale. Configure with `AEGIS_LLM`, `AEGIS_LLM_API_BASE`,
  `AEGIS_LLM_API_KEY`.
- A **typed decision model** (`aegis.decision`) — `choose` / `score` / `boolean`
  with a probability: the triage/validate/dedup oracle. **Jev** (TypeSafe's typed
  `/v1/decisions` API) is the native fit; it is used *only alongside* an LLM.

### Modes

Pick a mode; the decision model is never used alone:

```bash
aegis run --mode full-llm      --allow-egress   # one LLM plans AND decides
aegis run --mode llm+decision  --allow-egress   # LLM plans/writes, Jev decides
aegis run --mode static                         # fully offline/deterministic (tests, CI)
```

In both real modes a generative LLM is always in the loop (planning each step,
authoring rationale — visible in the dashboard's agent timeline). `--mode
llm+decision` routes the typed decisions to the decision model (`--decision-model
jev|basal`). `--backend {static,basal,jev,llm}` remains as the low-level decider
knob. Everything defaults to offline/localhost; remote deciders and non-localhost
LLM endpoints are refused unless `--allow-egress`.

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
exploitability chain, evidence and the per-finding decision trail), an
interactive Agent graph (select an agent for its trajectory, an inter-agent
message transcript, and an interleaved run timeline),
Hypotheses queue, the full **decision audit trail**, and the Tools catalog. See
[`ui/README.md`](ui/README.md).

Licensed under Apache-2.0.
