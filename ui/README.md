# Aegis dashboard (local-only)

A Vite + React + Tailwind dashboard over the Aegis unified report. It runs
**entirely locally** — nothing is hosted and no data leaves the machine.

## Run

```bash
# 1. produce a run for the dashboard to read (from the repo root):
aegis run --out ui/public/data            # or: aegis run --use-tools --out ui/public/data

# 2. start the dashboard:
cd ui
npm install
npm run dev                               # http://localhost:5173
```

It reads `ui/public/data/report.json` and `decisions.jsonl`. Re-run `aegis run
--out ui/public/data` to refresh; the page reloads the data on refresh.

## Views

- **Overview** — run KPIs, severity donut, OWASP distribution, per-engine
  rollup, top findings, rejections, and a degraded-run banner.
- **Findings** — filter/sort by severity, CVSS, OWASP, engine, exploitable;
  a detail drawer with the parsed CVSS vector, the 8-stage exploitability
  chain, evidence, and the decision trail for that finding.
- **Agent graph** — the dynamic engine's graph of agents, interactive: select
  any agent to inspect its step-by-step **trajectory**, read the inter-agent
  **message transcript** (the coordinator delegates, each sub-agent reports
  back), and follow one interleaved **run timeline** across all agents. Every
  event is derived from the real control flow, not fabricated.
- **Hypotheses** — the static engine's priority-ordered hypothesis queue and
  coverage ledger.
- **Decisions** — the full, replayable decision audit trail (every router
  decision: kind, probability, threshold, outcome, backend, cache hits).
- **Tools** — the 17 capability adapters and their run status.

## Build

```bash
npm run build        # -> dist/ (static, relative paths; open locally)
npm run preview
```
