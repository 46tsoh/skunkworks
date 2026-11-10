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

/**
 * Live transcript: poll data/events.jsonl so the agent view fills in real time
 * while a run is writing it (no server beyond the dev server). Returns the full
 * event list; empty until a run streams one.
 */
export function useLiveEvents(intervalMs = 1500) {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    let alive = true;
    let timer;
    let lastLen = -1;
    let stable = 0;
    const tick = async () => {
      let evs = null;
      try {
        evs = parseJsonl(await fetchText("data/events.jsonl"));
      } catch {
        /* no events file yet — fine */
      }
      if (!alive) return;
      if (evs) {
        if (evs.length !== lastLen) {
          lastLen = evs.length;
          stable = 0;
          setEvents(evs);
        } else {
          stable += 1;
        }
      }
      // Stop polling once the run is finished and the stream has settled, so a
      // completed run doesn't poll forever (this caused the live-view jank).
      const done = evs && evs.some((e) => e.type === "finish") && stable >= 3;
      if (alive && !done) timer = setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [intervalMs]);
  return events;
}

/** Reconstruct the agent graph from the event stream (agents appear as they
 *  spawn, so the graph grows live). */
export function agentsFromEvents(events) {
  const byId = {};
  for (const e of events) {
    if (e.type === "spawn") {
      byId[e.agent_id] = {
        id: e.agent_id, role: e.role, task: e.task,
        parent_id: e.parent_id ?? null, status: "running",
        steps_spent: 0, trajectory: [],
      };
    } else if (byId[e.agent_id]) {
      if (e.type === "status") byId[e.agent_id].status = e.status;
      else if (e.type === "tool_call" || e.type === "decision") byId[e.agent_id].steps_spent++;
    }
  }
  return Object.values(byId);
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
    // Unified agent transcript across both engines (orchestrator-owned), with a
    // fallback to the dynamic engine's own snapshot for older runs.
    transcript: report.transcript || (dyn.extra && dyn.extra.transcript) || [],
    hypotheses: (stat.extra && stat.extra.hypotheses) || [],
    coverage: (stat.extra && stat.extra.coverage) || {},
    toolRuns: engines.flatMap((e) =>
      ((e.extra && e.extra.tool_runs) || []).map((t) => ({ engine: e.name, ...t }))
    ),
    decisions: decisions || [],
  };
}
