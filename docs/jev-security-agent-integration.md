# Integrating the Jev decision model into Strix and RAPTOR

**Status:** research / design note
**Scope:** pure engineering — how to wire a fast "decision" model into two
open-source, LLM-driven security-analysis frameworks to cut cost and latency
and make their decision logic testable. **No offensive/red-team content**: this
note is about software architecture, not about attacking targets.

---

## 1. The three pieces

### Strix (`github.com/usestrix/strix`)
Open-source (Apache-2.0) autonomous **security-testing** agent, distributed as
the `strix-agent` PyPI package. Architecture highlights relevant to us:

- A **"Graph of Agents"** multi-agent system (recon / exploitation /
  post-exploitation specialists that share findings and run in parallel).
- A toolbelt: Caido-based HTTP proxy, browser automation, shell, a Python
  sandbox (Docker), recon/OSINT, SAST+DAST, and a **findings knowledge base**
  with CVSS scoring and OWASP classification.
- LLM provider is configured by environment: `STRIX_LLM` (provider-prefixed
  model string), `LLM_API_KEY`, `LLM_API_BASE`; settings persist in
  `~/.strix/cli-config.json`. LiteLLM appears to handle provider routing.
- Extension points: **Skills** (`SKILL.md` format, `npx skills add …`) and
  **MCP servers** (`~/.strix/mcp-servers.json`).

### RAPTOR (`github.com/gadievron/raptor`)
MIT-licensed autonomous security-research framework built *on top of* Claude
Code but "not tied to it" (`raptor.py` runs standalone). Relevant structure:

- Wraps **Semgrep** + **CodeQL** (static, optional SMT path-feasibility) and
  dynamic tools (`/binary`, `/fuzz`, `/crash-analysis`, `/frida`), SCA, and
  `/web`.
- A **hypothesis-driven audit engine** that tracks evidence and coverage.
- `/validate` runs an **eight-stage exploitability check**.
- `/agentic` chains mapping → investigation → assessment → exploitability →
  PoC/patch into one workflow.
- Per-run **cost caps** (`--max-cost-usd`, `/agentic` defaults to $10) and a
  dispatcher that holds provider credentials so workers never see API keys.
- Extension points: custom detection rules, specialist **personas**
  (`tiers/personas/`), a labeled regression corpus (`core/dataflow/corpus/`),
  and a mechanical `--no-llm` mode.

### Jev (TypeSafe AI)
A commercial **"System One" decision model** (early access Sept 2026, current
`jev-1.13.0`). It is *not* a chatbot: software calls it over an API with a
prompt plus structured options and it returns a **typed answer** — one of:

1. **choose-one** — pick one of N options,
2. **score** — a value on a scale,
3. **boolean** — probability that a yes/no statement is true,

each returned with a probability/confidence. Text-only input today. The
canonical usage pattern the vendor and reviewers describe is:

> **the LLM writes & plans, Jev decides, ordinary code acts.**

Independent testing (Towards Data Science) found Jev roughly on par with a
locally-run Qwen for latency, and TypeSafe has published no base model or
parameter count — so treat vendor speed/cost claims as unverified and design so
we are **not locked to Jev** (see §5).

> Note: the exact request/response JSON field names could not be pulled from the
> vendor write-ups in this environment (network policy blocked the blog hosts;
> only `raw.githubusercontent.com` and search summaries resolved). The reference
> code therefore isolates the wire format in one adapter
> (`reference/jev/decision_client.py`, `JevBackend`) behind clearly marked
> constants, so pinning it to the real API is a one-file change.

---

## 2. Why these fit together (the core thesis)

Strix and RAPTOR are expensive agent loops. A large share of their LLM calls are
**not** "generate code / write a plan" calls — they are **decisions**:

- *Which* agent / tool / persona do we invoke next? → **choose-one**
- Is this finding a true positive, or noise? → **boolean**
- Is this crash/path actually exploitable? → **boolean** (RAPTOR `/validate`)
- How severe is this? (CVSS-ish band, priority) → **score**
- Should the loop stop, continue, or escalate? → **boolean / choose-one**
- Are these two findings the same issue (dedupe)? → **boolean / choose-one**

These high-frequency, low-creativity decisions map exactly onto Jev's three
primitives. Routing them through a dedicated decision model (with an LLM-judge
fallback) is attractive for reasons that are all **code-quality / engineering**
wins rather than new capability:

| Problem today | What a decision layer buys |
|---|---|
| Every triage/routing decision burns metered LLM tokens | Offload to a cheap/fast model → RAPTOR's `--max-cost-usd` budget goes much further; Strix runs cost less |
| Decisions are free-form text parsed with regex/JSON-coercion → brittle | Typed outputs (`choice` + `probability`) → no parsing, no "model replied in prose" failures |
| Agent decisions are **non-deterministic and nearly untestable** | A decision client can be mocked; thresholds make outcomes assertable in unit tests |
| No record of *why* the agent branched | A single `DecisionRouter` emits a structured decision log (auditable, replayable) |
| Confidence is implicit | Explicit probability + per-decision **threshold** you can tune and calibrate |
| Each framework hardcodes its own ad-hoc judging | One shared, provider-agnostic interface reused by both |

---

## 3. Where exactly to wire it in

### 3.1 Strix
Concentrate on two hot paths; leave the creative work (writing exploits,
summarizing) on the main LLM.

1. **Agent-graph routing.** When the orchestrator decides which specialist to
   spawn or which tool to call next, that is a `choose-one` over a known,
   enumerable set. Replace the free-form "decide next step" prompt with a
   `router.choose(...)`. Keep an LLM path for the genuinely open-ended "what
   should we even try here" case.
2. **Findings triage.** The findings knowledge base already assigns CVSS/OWASP.
   Add a `boolean` gate ("is this a true positive worth reporting?") and a
   `score` for severity/priority *before* an expensive LLM write-up is
   generated. This is the single biggest token saver: it stops the agent from
   drafting PoCs/reports for noise.

Delivery mechanism that respects Strix's design: ship it as a **Strix Skill**
(the `SKILL.md` extension point) or an **MCP server** exposing
`decide_route` / `triage_finding` tools, so no fork of core is required. A
deeper integration can call the router directly from the orchestrator.

### 3.2 RAPTOR
RAPTOR is almost purpose-built for this because its decisions are already
*staged and explicit*.

1. **The `/validate` eight-stage exploitability check.** Each stage is a gate —
   a yes/no with evidence. Model each as a calibrated Jev `boolean`
   (`reference/jev/integrations/raptor_gates.py` shows the pattern). An early
   gate failing short-circuits the chain *without* spending LLM budget on later
   stages. Thresholds per stage let you trade false-positive vs false-negative
   per gate.
2. **Hypothesis-driven audit engine.** It tracks hypotheses with evidence and
   coverage; "is this hypothesis worth pursuing next / with what priority" is a
   `score` + `choose-one`. Routing attention this way reduces wasted
   investigation passes.
3. **Dataflow corpus → calibration data.** `core/dataflow/corpus/` is a
   *labeled* set of findings. That is exactly what you need to **calibrate
   thresholds** and to A/B the decision layer against ground truth (see §6). It
   also doubles as a regression suite for the decision logic.

Delivery mechanism: RAPTOR already has an "LLM dispatcher in the parent process"
boundary and a persona/rules extension model. Add the decision client **behind
the dispatcher** so workers call `decide(...)` over the existing socket and
still never hold API keys. Mechanical `--no-llm` runs can use a `StaticBackend`
(deterministic thresholds) to keep that mode truly LLM-free.

---

## 4. Proposed shared component (this repo's reference implementation)

Rather than fork either project, build **one small, dependency-light library**
both can depend on. Layout under `reference/jev/`:

```
reference/jev/
  decision_client.py     # provider-agnostic client: Jev + fallbacks
  router.py              # DecisionRouter: cache, threshold, logging, metrics
  integrations/
    strix_decisions.py   # illustrative Strix routing/triage shim
    raptor_gates.py      # illustrative RAPTOR /validate gate chain
  tests/
    test_router.py       # runs with stdlib only (no network, no Jev)
  README.md
```

Design principles:

- **Dependency inversion.** Core depends on a `DecisionBackend` protocol, not on
  TypeSafe. Backends: `JevBackend` (real API), `LLMJudgeBackend` (wraps *any*
  callable you already have — LiteLLM in Strix, the dispatcher in RAPTOR),
  `StaticBackend` (deterministic, for tests/`--no-llm`).
- **Graceful degradation.** `DecisionClient(primary, fallback)` — if Jev is
  unconfigured, times out, or errors, fall back to the LLM judge (or static).
  Neither framework should ever hard-fail because a decision backend is down.
- **Everything observable.** `DecisionRouter` writes a JSONL decision log
  (`kind`, options, chosen, probability, threshold, backend, latency, cache
  hit). This is the auditability win.
- **Thresholds as config, not code.** Each decision *kind* has a threshold;
  `record_outcome()` lets you feed ground truth back for calibration.
- **Testable.** The whole thing runs offline with `StaticBackend`; see
  `tests/test_router.py`.

---

## 5. Risks & guardrails (engineering)

- **Vendor lock-in / unproven claims.** Jev has no public base model and
  independent latency parity with a local Qwen. Mitigation: the adapter makes
  Jev *one* backend; you can run entirely on `LLMJudgeBackend` or a local model
  and still keep all the structural benefits (typing, thresholds, logging).
- **Calibration debt.** A miscalibrated boolean gate silently drops real
  findings (false negatives) — worse than wasted tokens. Mitigation: never ship
  a gate without calibrating its threshold on labeled data, default thresholds
  conservative (bias toward *keeping* findings), and keep the decision log so
  every dropped finding is auditable/replayable.
- **Data sent to a third party.** Routing decisions may include snippets of the
  target's code or responses. Sending those to TypeSafe is a data-egress
  decision each operator must make deliberately. Mitigation: `LLMJudgeBackend`
  /`StaticBackend` keep everything in-house; the client never sends anything a
  backend doesn't explicitly build; document this clearly.
- **Text-only input.** Jev takes text; binary/crash artifacts must be
  summarized to text first (which RAPTOR already does for its LLM calls — reuse
  that).

---

## 6. Suggested rollout

1. **Shadow mode.** Run the decision layer in parallel with the existing LLM
   path; log both, change nothing. Compare against `core/dataflow/corpus/`
   labels (RAPTOR) and Strix's own findings DB.
2. **Calibrate** thresholds per decision kind from the shadow logs.
3. **Promote** the cheapest, best-calibrated decisions first (findings triage,
   `/validate` gates) behind a feature flag / env toggle.
4. **Measure**: tokens-per-run, wall-clock, and — critically — true/false
   positive rates vs the LLM-only baseline. Keep the LLM path one flag away.

---

## 7. References

- Strix — [github.com/usestrix/strix](https://github.com/usestrix/strix),
  [strix-agent on PyPI](https://pypi.org/project/strix-agent/),
  [Help Net Security overview](https://www.helpnetsecurity.com/?p=348469)
- RAPTOR — [github.com/gadievron/raptor](https://github.com/gadievron/raptor),
  [docs](https://www.mintlify.com/gadievron/raptor/introduction)
- Jev / TypeSafe — [Lindy: Jev vs LLM](https://www.lindy.ai/blog/jev-vs-llm),
  [pooyagolchian: what is the Jev model](https://pooyagolchian.com/blog/what-is-jev-ai-decision-model-2026/),
  [aibuilderclub: Jev engineering guide](https://www.aibuilderclub.com/blog/jev-engineering-guide)
  (vendor/aggregator sources; verify API specifics against TypeSafe's own docs —
  these hosts were blocked by this environment's network policy).
