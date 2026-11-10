import { Panel, Tag, cx } from "../lib/ui.jsx";

const STATUS_COLOR = {
  accepted: "var(--color-ok)",
  rejected: "var(--color-sev-high)",
  queued: "var(--color-faint)",
};

export default function Hypotheses({ model }) {
  const { hypotheses, coverage } = model;
  const sorted = [...hypotheses].sort((a, b) => b.priority - a.priority);
  const maxP = Math.max(1, ...hypotheses.map((h) => h.priority));

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Hypotheses" value={hypotheses.length} />
        <Stat label="Accepted" value={hypotheses.filter((h) => h.status === "accepted").length}
              color="var(--color-ok)" />
        <Stat label="Components examined" value={coverage.examined ?? 0} />
      </div>

      <Panel title="Static engine — hypothesis queue (priority order)">
        <ul className="space-y-2.5">
          {sorted.map((h) => (
            <li key={h.id} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[12px] text-[var(--color-faint)]">{h.id}</span>
                  <span className="text-[13px]">#{h.seq}</span>
                </div>
                <span className="text-[12px] font-medium capitalize" style={{ color: STATUS_COLOR[h.status] }}>
                  {h.status}
                </span>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-bg)]">
                  <div className={cx("grow h-full rounded-full")}
                       style={{ width: `${(h.priority / maxP) * 100}%`,
                                background: STATUS_COLOR[h.status] || "var(--color-accent)" }} />
                </div>
                <span className="w-14 text-right text-[12px] tabular-nums text-[var(--color-muted)]">
                  P {h.priority.toFixed(1)}
                </span>
              </div>
            </li>
          ))}
          {sorted.length === 0 && <li className="text-[13px] text-[var(--color-muted)]">No hypotheses in this run.</li>}
        </ul>
      </Panel>

      {coverage.components && coverage.components.length > 0 && (
        <Panel title="Coverage ledger">
          <div className="flex flex-wrap gap-1.5">
            {coverage.components.map((c) => <Tag key={c}>{c}</Tag>)}
          </div>
        </Panel>
      )}
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div className="rounded-[var(--radius-card)] border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="text-[12px] uppercase tracking-wide text-[var(--color-faint)]">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" style={color ? { color } : undefined}>{value}</div>
    </div>
  );
}
