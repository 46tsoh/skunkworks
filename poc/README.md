# POC: Strix + RAPTOR + decision-model triage pipeline

A self-contained proof of concept that recreates, in original code, the
**decision-shaped** patterns from two security-analysis frameworks and routes
every decision through a typed decision model (Jev / basal-omni) via
[`reference/jev`](../reference/jev).

It is a **defensive engineering demo**: it runs on *sample finding data*, does
no scanning, no exploitation, and reaches no target. It runs fully offline and
deterministically; basal-omni/Jev drop in behind one flag.

## What it combines

| Pattern | From | Where | Decision type |
|---|---|---|---|
| True-positive **triage** gate | Strix | `pipeline.py` | boolean |
| **Hypothesis** posterior from evidence | RAPTOR (`hypothesis_validation`) | `hypothesis.py` | score (0..1) |
| LLM-style **dedup** (`check_duplicate`) | Strix (`report/dedupe.py`) | `dedupe.py` | boolean + confidence |
| Staged **exploitability validation** (short-circuits) | RAPTOR (`exploitability_validation` / `/validate`) | `validate.py` | boolean per stage |
| **CVSS v3.1** base score + severity | Strix (`cvss` lib) | `cvss.py` | deterministic |

All boolean/score decisions go through the `DecisionRouter`, so the run is
**logged** (JSONL), **cached**, **threshold-tuned**, and reproducible.

## Pipeline order

```
candidate -> triage gate -> hypothesis posterior -> dedupe -> exploitability
          -> CVSS score -> ranked report   (first failing step rejects/collapses)
```

## Run it

```bash
# sample data, offline deterministic backend
python -m poc.cli

# write report.json + decisions.jsonl
python -m poc.cli --out ./poc_out

# point decisions at a local basal-omni server (falls back to the stand-in)
python -m poc.cli --backend basal
```

Example output (sample data):

```
candidates=7  accepted=4  rejected=3  decisions=47 (cache hits 0)
-- Accepted (ranked) --
  [Critical  9.8] F1 SQL injection in login handler        EXPLOITABLE
  [Critical  9.3] F7 SSRF in webhook URL fetch             EXPLOITABLE
  [Medium    6.5] F5 IDOR on invoice retrieval             EXPLOITABLE
  [Low       3.6] F6 Potential buffer over-read in log parser  info (stopped@2)
-- Rejected --
  F2  <dedupe: duplicate of F1>
  F3  <triage: likely false positive>
  F4  <hypothesis: posterior 0.35 < 0.5>
```

## The backends

- **`static`** (default) — `HintBackend`, a deterministic stand-in that resolves
  each decision from the sample data's ground-truth `hints` via a
  `[ref=...]` tag appended to the decision statement. No network, no model.
- **`basal`** — `BasalOmniBackend` (self-hosted, open-weight) primary, stand-in
  fallback so the demo always completes.
- **`jev`** — hosted `JevBackend` primary, stand-in fallback.

Real backends read the natural-language statement and ignore the `[ref=...]`
tag; it exists only so the offline stand-in can be deterministic. Swapping
backends changes nothing else — that is the point of depending on the
`DecisionBackend` protocol.

## Tests

```bash
python -m unittest discover -s poc/tests
```

## Scope / honesty

This POC **recreates patterns**; it is not a port of either framework's
internals. The sample findings are illustrative descriptions, not live
vulnerabilities, and no step attacks anything. See
[`docs/jev-security-agent-integration.md`](../docs/jev-security-agent-integration.md)
for how these same decision points map onto the real Strix and RAPTOR code.
