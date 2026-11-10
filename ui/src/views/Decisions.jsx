import { useMemo, useState } from "react";
import { Panel, Tag, cx } from "../lib/ui.jsx";

export default function Decisions({ model }) {
  const { decisions } = model;
  const [kind, setKind] = useState("all");
  const [op, setOp] = useState("all");

  const kinds = useMemo(() => [...new Set(decisions.map((d) => d.kind).filter(Boolean))], [decisions]);
  const ops = useMemo(() => [...new Set(decisions.map((d) => d.op).filter(Boolean))], [decisions]);

  const rows = decisions.filter((d) => d.type === "decision"
    && (kind === "all" || d.kind === kind) && (op === "all" || d.op === op));

  const byBackend = decisions.reduce((a, d) => {
    if (d.backend) a[d.backend] = (a[d.backend] || 0) + 1;
    return a;
  }, {});

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Sel value={kind} onChange={setKind} options={[["all", "All kinds"], ...kinds.map((k) => [k, k])]} />
        <Sel value={op} onChange={setOp} options={[["all", "All ops"], ...ops.map((o) => [o, o])]} />
        <div className="ml-auto flex gap-1.5">
          {Object.entries(byBackend).map(([b, n]) => <Tag key={b} tone="accent">{b}: {n}</Tag>)}
        </div>
      </div>

      <Panel title={`Decision audit trail — ${rows.length} of ${decisions.length}`}>
        <p className="mb-3 text-[13px] text-[var(--color-muted)]">
          Every branch both engines took, routed through the one decision router — kind, inputs, outcome,
          probability, threshold, backend. A replayable record of <em>why</em> the pipeline decided as it did.
        </p>
        <div className="max-h-[62vh] overflow-auto rounded-lg border border-[var(--color-border)]">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 bg-[var(--color-surface-2)]">
              <tr className="text-[11px] uppercase tracking-wide text-[var(--color-faint)]">
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Op</th>
                <th className="px-3 py-2 text-right">Prob.</th>
                <th className="px-3 py-2 text-right">Thr.</th>
                <th className="px-3 py-2 text-left">Outcome</th>
                <th className="px-3 py-2 text-left">Backend</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d, i) => {
                const decided = d.outcome?.decision;
                return (
                  <tr key={i} className="border-t border-[var(--color-border)]/60">
                    <td className="px-3 py-1.5 font-mono text-[12px]">{d.kind}</td>
                    <td className="px-3 py-1.5 text-[var(--color-muted)]">{d.op}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums">
                      {d.probability != null ? d.probability.toFixed(2)
                        : d.outcome?.value != null ? d.outcome.value.toFixed(2) : "—"}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums text-[var(--color-faint)]">
                      {d.threshold != null ? d.threshold.toFixed(2) : "—"}</td>
                    <td className="px-3 py-1.5">
                      {typeof decided === "boolean"
                        ? <span className={cx("font-medium")}
                                style={{ color: decided ? "var(--color-ok)" : "var(--color-sev-high)" }}>
                            {decided ? "pass" : "drop"}</span>
                        : <span className="text-[var(--color-muted)]">
                            {d.outcome?.option ?? (d.outcome?.value != null ? d.outcome.value.toFixed(2) : "—")}</span>}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className="inline-flex items-center gap-1 text-[12px] text-[var(--color-muted)]">
                        {d.backend}{d.cache_hit && <span title="cache hit" className="text-[var(--color-accent)]">⚡</span>}
                      </span>
                    </td>
                  </tr>
                );
              })}
              {rows.length === 0 && (
                <tr><td colSpan={6} className="px-3 py-8 text-center text-[var(--color-muted)]">
                  No decisions logged. Run <code className="font-mono">aegis run --out ui/public/data</code>.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function Sel({ value, onChange, options }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-[13px] focus:border-[var(--color-accent)] focus:outline-none">
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}
