import { Panel, Tag, cx } from "../lib/ui.jsx";

const ROLE_LABEL = {
  coordinator: "Coordinator",
  recon: "Recon",
  exploitation: "Exploitation",
  post_exploitation: "Post-exploitation",
};

export default function Agents({ model }) {
  const { graph, engines } = model;
  const dyn = engines.find((e) => e.name === "dynamic") || {};
  const root = graph.find((n) => !n.parent_id);
  const children = graph.filter((n) => n.parent_id);

  return (
    <div className="space-y-5">
      <Panel title="Dynamic engine — graph of agents"
             action={<Tag tone="accent">{dyn.extra?.steps_spent ?? 0} steps</Tag>}>
        {graph.length === 0 ? (
          <p className="text-[13px] text-[var(--color-muted)]">No agent graph in this run.</p>
        ) : (
          <div className="flex flex-col items-center gap-0 py-2">
            {root && <AgentNode node={root} root />}
            {children.length > 0 && (
              <>
                <div className="h-6 w-px bg-[var(--color-border-strong)]" />
                <div className="relative flex flex-wrap items-start justify-center gap-6">
                  <div className="absolute left-0 right-0 top-0 mx-auto h-px bg-[var(--color-border-strong)]"
                       style={{ width: children.length > 1 ? "70%" : 0 }} />
                  {children.map((n) => (
                    <div key={n.id} className="flex flex-col items-center">
                      <div className="h-6 w-px bg-[var(--color-border-strong)]" />
                      <AgentNode node={n} />
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 sm:grid-cols-3">
        {graph.map((n) => (
          <div key={n.id} className="rounded-[var(--radius-card)] border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-semibold">{ROLE_LABEL[n.role] || n.role}</span>
              <StatusDot status={n.status} />
            </div>
            <p className="mt-1 text-[12px] text-[var(--color-muted)]">{n.task}</p>
            <div className="mt-2 text-[11px] text-[var(--color-faint)]">
              {n.id} · {n.steps_spent} step{n.steps_spent === 1 ? "" : "s"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AgentNode({ node, root }) {
  return (
    <div className={cx("lift w-56 rounded-xl border bg-[var(--color-surface-2)] px-4 py-3 text-center",
      root ? "border-[color-mix(in_oklab,var(--color-accent)_50%,transparent)]" : "border-[var(--color-border-strong)]")}>
      <div className="flex items-center justify-center gap-2">
        <span className="text-[13px] font-semibold" style={root ? { color: "var(--color-accent)" } : undefined}>
          {ROLE_LABEL[node.role] || node.role}
        </span>
        <StatusDot status={node.status} />
      </div>
      <div className="mt-0.5 text-[11px] text-[var(--color-faint)]">{node.task}</div>
    </div>
  );
}

function StatusDot({ status }) {
  const color = status === "completed" ? "var(--color-ok)"
    : status === "running" ? "var(--color-accent)" : "var(--color-faint)";
  return (
    <span className="inline-flex items-center gap-1 text-[11px]" style={{ color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />{status}
    </span>
  );
}
