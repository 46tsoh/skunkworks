# skunkworks

## Jev × security-agent integration (research + reference)

Research into integrating TypeSafe's **Jev** decision model with the
open-source security-analysis frameworks **Strix** and **RAPTOR** — scoped to
*pure engineering / code improvements* (cost, latency, testability), not
offensive use.

- **Research note:** [`docs/jev-security-agent-integration.md`](docs/jev-security-agent-integration.md)
- **Reference implementation:** [`reference/jev/`](reference/jev/) — a
  provider-agnostic typed-decision layer with offline tests.

```bash
python -m unittest discover -s reference/jev/tests
```
