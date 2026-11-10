import { Panel, StatCard, SeverityDonut, BarList, SeverityBadge, EngineTag } from "../lib/ui.jsx";

export default function Overview({ model, onOpenFinding, goto }) {
  const { metrics, summary, accepted, rejected, engines } = model;
  const sev = summary.severity_counts || {};
  const engineCounts = summary.engine_counts || {};
  const exploitable = accepted.filter((f) => f.exploitable).length;

  const owaspItems = Object.entries(
    accepted.reduce((acc, f) => {
      const k = f.owasp || "Unclassified";
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {})
  )
    .map(([label, value]) => ({ label: label.replace(/^A\d+:\d+-?/, (m) => m), value }))
    .sort((a, b) => b.value - a.value);

  const top = [...accepted].slice(0, 5);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Findings" value={metrics.accepted ?? accepted.length}
                  hint={`${exploitable} exploitable`} />
        <StatCard label="Critical + High" value={(sev.Critical || 0) + (sev.High || 0)}
                  accent="var(--color-sev-critical)" hint="highest priority" />
        <StatCard label="Cross-engine dedup" value={metrics.cross_engine_dedup ?? 0}
                  hint="duplicates collapsed" />
        <StatCard label="Decisions" value={metrics.decisions ?? 0}
                  accent="var(--color-accent)"
                  hint={`${metrics.decision_cache_hits ?? 0} cache hits`} />
      </div>

      {metrics.llm_usage && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 rounded-[var(--radius-card)] border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2.5 text-[12px]">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-faint)]">LLM usage</span>
          <span className="font-mono text-[var(--color-accent)]">{metrics.llm_usage.model}</span>
          <span className="text-[var(--color-muted)]">
            <span className="font-semibold text-[var(--color-ink)] tabular-nums">{metrics.llm_usage.total_tokens.toLocaleString()}</span> tokens
          </span>
          <span className="text-[var(--color-faint)] tabular-nums">
            {metrics.llm_usage.input_tokens.toLocaleString()} in · {metrics.llm_usage.output_tokens.toLocaleString()} out
          </span>
          <span className="text-[var(--color-faint)] tabular-nums">{metrics.llm_usage.calls} calls</span>
        </div>
      )}

      {metrics.degraded && (
        <div className="rounded-[var(--radius-card)] border px-4 py-3 text-[13px]"
             style={{ borderColor: "color-mix(in oklab, var(--color-sev-high) 45%, transparent)",
                      background: "color-mix(in oklab, var(--color-sev-high) 12%, transparent)",
                      color: "var(--color-sev-high)" }}>
          Run degraded — {(metrics.tool_failures || []).length} tool(s) did not complete. Results may be incomplete.
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Severity" className="lg:col-span-1">
          <SeverityDonut counts={sev} />
        </Panel>

        <Panel title="OWASP Top 10 (2021)" className="lg:col-span-1">
          {owaspItems.length ? <BarList items={owaspItems} /> :
            <p className="text-[13px] text-[var(--color-muted)]">No classified findings.</p>}
        </Panel>

        <Panel title="Engines" className="lg:col-span-1"
               action={<button onClick={() => goto("agents")}
                 className="tap text-[12px] text-[var(--color-accent)] hover:underline">graph →</button>}>
          <div className="space-y-3">
            {engines.map((e) => (
              <div key={e.name} className="flex items-center justify-between rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <EngineTag engine={e.name} />
                  <span className="text-[12px] text-[var(--color-faint)]">{e.kind}</span>
                </div>
                <div className="flex items-center gap-4 text-[13px] tabular-nums">
                  <span className="text-[var(--color-ok)]">{e.accepted} kept</span>
                  <span className="text-[var(--color-muted)]">{e.rejected} dropped</span>
                </div>
              </div>
            ))}
            <BarList color="var(--color-accent)"
              items={Object.entries(engineCounts).map(([label, value]) => ({ label, value }))} />
          </div>
        </Panel>
      </div>

      <Panel title="Top findings"
             action={<button onClick={() => goto("findings")}
               className="tap text-[12px] text-[var(--color-accent)] hover:underline">all findings →</button>}>
        <div className="divide-y divide-[var(--color-border)]">
          {top.map((f) => (
            <button key={f.id} onClick={() => onOpenFinding(f.id)}
              className="tap flex w-full items-center gap-3 py-2.5 text-left hover:bg-[var(--color-surface-2)]/60 rounded-md px-1">
              <span className="tabular-nums text-[13px] font-semibold" style={{ width: 44 }}>
                {f.cvss_score.toFixed(1)}
              </span>
              <SeverityBadge severity={f.severity} />
              <span className="flex-1 truncate text-[14px]">{f.title}</span>
              <EngineTag engine={f.source_engine} />
              {f.exploitable && (
                <span className="text-[11px] font-semibold" style={{ color: "var(--color-sev-critical)" }}>
                  EXPLOITABLE
                </span>
              )}
            </button>
          ))}
        </div>
      </Panel>

      {rejected.length > 0 && (
        <Panel title={`Rejected (${rejected.length})`}>
          <ul className="space-y-1.5 text-[13px]">
            {rejected.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <span className="rounded border border-[var(--color-border-strong)] px-1.5 py-0.5 text-[11px] text-[var(--color-faint)]">
                  {r.stage}
                </span>
                <span className="text-[var(--color-muted)]">{r.title}</span>
                <span className="text-[var(--color-faint)]">— {r.reason}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
