# `reference/jev` — typed-decision layer for LLM security agents

Reference implementation for the design in
[`docs/jev-security-agent-integration.md`](../../docs/jev-security-agent-integration.md).

It gives Strix and RAPTOR a single, provider-agnostic way to make the
high-frequency **decisions** in their agent loops (routing, findings triage,
`/validate` gates, severity scoring) as **typed** calls — choose-one / score /
yes-no — instead of free-form LLM prompts. The payoff is engineering, not new
capability: lower cost, lower latency, and decision logic that is observable,
tunable, and **unit-testable**.

> This is reference/illustrative code. The core (`decision_client.py`,
> `router.py`) is runnable and tested; the `integrations/` shims show the exact
> call sites to target in each upstream project and are not drop-in patches.

## Layout

| File | Purpose |
|---|---|
| `decision_client.py` | Provider-agnostic client. Backends: `JevBackend` (hosted TypeSafe API), `BasalOmniBackend` (open-weight, **self-hosted**, multimodal — recommended default for sensitive targets), `LLMJudgeBackend` (wraps any completion callable), `StaticBackend` (offline/tests). `DecisionClient` adds primary→fallback degradation. |
| `router.py` | `DecisionRouter`: per-kind thresholds, caching, structured JSONL decision log, metrics, and a `record_outcome` calibration hook. |
| `integrations/strix_decisions.py` | Strix routing + findings-triage helpers. |
| `integrations/raptor_gates.py` | RAPTOR eight-stage `/validate` gate chain + hypothesis scoring. |
| `tests/test_router.py` | Offline tests (stdlib only). |

## Quick start

```python
from reference.jev import DecisionClient, DecisionRouter, LLMJudgeBackend, JevBackend

# Jev primary, your existing LLM as fallback (never hard-fails):
client = DecisionClient(
    primary=JevBackend(),                       # reads JEV_API_KEY / JEV_MODEL
    fallback=LLMJudgeBackend(complete=my_llm),  # any `str -> str` callable
)
router = DecisionRouter(
    client,
    thresholds={"strix.triage_true_positive": 0.35},
    log_path="decisions.jsonl",
)

keep = router.gate("strix.triage_true_positive", "This is a genuine finding: ...")
```

Fully offline (no key, no network), e.g. RAPTOR `--no-llm`:

```python
from reference.jev import DecisionClient, DecisionRouter, StaticBackend
router = DecisionRouter(DecisionClient(StaticBackend(boolean_fn=lambda s: 0.5)))
```

## Running the tests

```bash
python -m unittest discover -s reference/jev/tests
```

## Pinning the Jev wire format

The exact Jev request/response field names are isolated at the top of
`decision_client.py` (`_JEV_*` paths and `_RESP_*` keys). Vendor-doc hosts were
unreachable from the build environment, so confirm these against TypeSafe's
official API reference and adjust in that one file.
