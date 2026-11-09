# skunkworks

## Jev × security-agent integration (research + reference)

Research into integrating TypeSafe's **Jev** decision model with the
open-source security-analysis frameworks **Strix** and **RAPTOR** — scoped to
*pure engineering / code improvements* (cost, latency, testability), not
offensive use.

- **Research note:** [`docs/jev-security-agent-integration.md`](docs/jev-security-agent-integration.md)
- **Reference implementation:** [`reference/jev/`](reference/jev/) — a
  provider-agnostic typed-decision layer with offline tests.
- **POC:** [`poc/`](poc/) — a runnable pipeline that recreates Strix + RAPTOR
  decision patterns (triage, hypothesis posterior, dedup, staged exploitability
  validation, CVSS) with every decision routed through the decision model.

```bash
python -m unittest discover -s reference/jev/tests   # decision layer
python -m unittest discover -s poc/tests             # POC pipeline
python -m poc.cli                                    # run the demo
```
