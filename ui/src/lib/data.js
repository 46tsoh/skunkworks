import { useEffect, useState } from "react";

const BASE = import.meta.env.BASE_URL || "/";

async function fetchText(path) {
  const res = await fetch(BASE + path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.text();
}

function parseJsonl(text) {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/** Load report.json + decisions.jsonl from ./data/ (written by `aegis run --out`). */
export function useAegisData() {
  const [state, setState] = useState({ loading: true, error: null, report: null, decisions: [] });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const report = JSON.parse(await fetchText("data/report.json"));
        let decisions = [];
        try {
          decisions = parseJsonl(await fetchText("data/decisions.jsonl"));
        } catch {
          decisions = [];
        }
        if (alive) setState({ loading: false, error: null, report, decisions });
      } catch (error) {
        if (alive) setState({ loading: false, error: String(error), report: null, decisions: [] });
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return state;
}

/** Derived, view-ready slices of the report. */
export function deriveModel(report, decisions) {
  if (!report) return null;
  const run = report.run || {};
  const engines = run.engines || [];
  const byName = Object.fromEntries(engines.map((e) => [e.name, e]));
  const dyn = byName.dynamic || {};
  const stat = byName.static || {};
  return {
    run,
    metrics: report.metrics || {},
    summary: report.summary || {},
    accepted: report.accepted || [],
    rejected: report.rejected || [],
    engines,
    graph: (dyn.extra && dyn.extra.graph) || [],
    hypotheses: (stat.extra && stat.extra.hypotheses) || [],
    coverage: (stat.extra && stat.extra.coverage) || {},
    toolRuns: engines.flatMap((e) =>
      ((e.extra && e.extra.tool_runs) || []).map((t) => ({ engine: e.name, ...t }))
    ),
    decisions: decisions || [],
  };
}
