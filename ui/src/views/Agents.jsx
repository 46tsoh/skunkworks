import { useMemo, useState } from "react";
import { Panel, Tag } from "../lib/ui.jsx";
import { useLiveEvents, agentsFromEvents } from "../lib/data.js";

const ROLE_LABEL = {
  coordinator: "Coordinator",
  recon: "Recon",
  exploitation: "Exploitation",
  post_exploitation: "Post-exploitation",
};

function statusColor(status) {
  return status === "completed" ? "var(--color-ok)"
    : status === "running" ? "var(--color-accent)"
    : "var(--color-faint)";
}

export default function Agents({ model }) {
  const { engines } = model;
  const dyn = engines.find((e) => e.name === "dynamic") || {};

  // Live stream wins when it's richer than the loaded report (i.e. a run is
  // writing events.jsonl right now); otherwise fall back to the report.
  const liveEvents = useLiveEvents();
  const reportTranscript = model.transcript || [];
  const live = liveEvents.length > reportTranscript.length;
  const transcript = live ? liveEvents : reportTranscript;
  const graph = useMemo(
    () => (live ? agentsFromEvents(liveEvents) : model.graph || []),
    [live, liveEvents, model.graph]
  );

  const root = graph.find((n) => !n.parent_id) || graph[0];
  const children = graph.filter((n) => n.parent_id);

  const [selectedId, setSelectedId] = useState(root?.id ?? null);
  const roleOf = useMemo(
    () => Object.fromEntries(graph.map((n) => [n.id, n.role])),
    [graph]
  );
  const selected = graph.find((n) => n.id === selectedId) || root || null;
  const forAgent = useMemo(
    () => transcript.filter((e) => e.agent_id === selectedId),
    [transcript, selectedId]
  );

  if (graph.length === 0) {
    return (
      <Panel title="Dynamic engine — graph of agents">
        <p className="text-[13px] text-[var(--color-muted)]">No agent graph in this run.</p>
      </Panel>
    );
  }

  const hasTranscript = transcript.length > 0;

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_400px]">
        <Panel
          title="Dynamic engine — graph of agents"
          action={
            <div className="flex items-center gap-2">
              {live && (
                <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium"
                      style={{ color: "var(--color-ok)", background: "color-mix(in oklab, var(--color-ok) 14%, transparent)" }}>
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full" style={{ background: "var(--color-ok)" }} />
                  live
                </span>
              )}
              <Tag tone="accent">{transcript.length} events</Tag>
            </div>
          }
        >
          <p className="mb-3 text-[12px] text-[var(--color-faint)]">
            Select an agent to read its transcript.
          </p>
          <AgentGraph root={root} children={children} selectedId={selectedId} onSelect={setSelectedId} />
        </Panel>

        {selected && (
          <Panel title="Agent transcript" className="lg:sticky lg:top-4 lg:self-start">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-[15px] font-semibold">{ROLE_LABEL[selected.role] || selected.role}</h3>
                <p className="mt-0.5 text-[12px] text-[var(--color-muted)]">{selected.task}</p>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1.5 text-[12px] font-medium"
                    style={{ color: statusColor(selected.status) }}>
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: statusColor(selected.status) }} />
                {selected.status}
              </span>
            </div>
            <div className="mt-3 flex items-center gap-4 border-y border-[var(--color-border)] py-2 text-[12px]">
              <span className="font-mono text-[var(--color-faint)]">{selected.id}</span>
              <span className="text-[var(--color-muted)]">
                <span className="font-semibold text-[var(--color-ink)] tabular-nums">{selected.steps_spent}</span> steps
              </span>
              <span className="text-[var(--color-muted)]">
                <span className="font-semibold text-[var(--color-ink)] tabular-nums">{forAgent.length}</span> events
              </span>
            </div>
            {hasTranscript
              ? <Transcript events={forAgent} roleOf={roleOf} compact />
              : <LegacyTrajectory node={selected} />}
          </Panel>
        )}
      </div>

      {hasTranscript && (
        <Panel title="Run transcript">
          <Transcript events={transcript} roleOf={roleOf} withRole
                      onPickAgent={setSelectedId} selectedId={selectedId} />
        </Panel>
      )}
    </div>
  );
}

/* ---- the event transcript (Strix-style per-agent stream) ---------------- */

function Transcript({ events, roleOf, compact, withRole, onPickAgent, selectedId }) {
  if (events.length === 0) {
    return <p className="mt-3 text-[13px] text-[var(--color-faint)]">No transcript for this agent.</p>;
  }
  return (
    <div className={compact ? "mt-3 space-y-2" : "space-y-2"}>
      {events.map((e, i) => (
        <EventRow key={i} e={e} role={roleOf[e.agent_id]} withRole={withRole}
                  dimmed={withRole && selectedId && e.agent_id !== selectedId}
                  onPickAgent={onPickAgent} />
      ))}
    </div>
  );
}

function EventRow({ e, role, withRole, dimmed, onPickAgent }) {
  const roleName = ROLE_LABEL[role] || role || e.agent_id;
  const head = withRole && (
    <button
      onClick={() => onPickAgent && onPickAgent(e.agent_id)}
      className="tap mr-2 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-faint)] hover:text-[var(--color-ink)]"
      style={{ width: 86, textAlign: "left" }}
    >
      {roleName}
    </button>
  );
  const wrap = (inner) => (
    <div className="flex items-start" style={{ opacity: dimmed ? 0.45 : 1 }}>
      {head}
      <div className="min-w-0 flex-1">{inner}</div>
    </div>
  );

  switch (e.type) {
    case "assistant":
      return wrap(
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-[13px] leading-relaxed text-[var(--color-ink)]">
          {e.text}
        </div>
      );
    case "think":
      return wrap(
        <div className="flex gap-2 px-1 text-[12px] italic text-[var(--color-faint)]">
          <span className="not-italic" style={{ color: "var(--color-accent)" }}>think</span>
          <span>{e.text}</span>
        </div>
      );
    case "tool_call":
      return wrap(
        <div className="font-mono text-[12px] text-[var(--color-muted)]">
          <span style={{ color: "var(--color-accent)" }}>▸ {e.tool}</span>
          <span className="text-[var(--color-faint)]">({argStr(e.args)})</span>
        </div>
      );
    case "tool_output":
      return wrap(
        <div className="pl-3 text-[12px] text-[var(--color-faint)]">
          <span style={{ color: e.status === "ok" ? "var(--color-ok)" : "var(--color-sev-high)" }}>⇒ </span>
          {e.summary}
        </div>
      );
    case "decision":
      return wrap(
        <div className="flex flex-wrap items-center gap-2 text-[12px]">
          <span className="rounded border border-[var(--color-border-strong)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--color-faint)]">
            {e.kind}
          </span>
          <span className="font-medium" style={{ color: outcomeColor(e.outcome) }}>{e.outcome}</span>
          {e.probability != null && (
            <span className="font-mono text-[var(--color-faint)] tabular-nums">p={Number(e.probability).toFixed(2)}</span>
          )}
          {e.backend && <span className="text-[var(--color-faint)]">· {e.backend}</span>}
        </div>
      );
    case "message":
      return wrap(
        <div className="text-[12px] text-[var(--color-muted)]">
          <span className="text-[var(--color-faint)]">{e.to ? `→ ${label(e.to)}` : e.from ? `← ${label(e.from)}` : ""}</span>{" "}
          {e.text}
        </div>
      );
    case "finding":
      return wrap(
        <div className="flex items-center gap-2 rounded-lg px-2 py-1 text-[12px]"
             style={{ background: "color-mix(in oklab, var(--color-sev-critical) 10%, transparent)" }}>
          <span className="font-semibold" style={{ color: "var(--color-sev-critical)" }}>filed</span>
          <span className="font-mono text-[11px] text-[var(--color-faint)]">{e.id}</span>
          <span className="truncate text-[var(--color-ink)]">{e.title}</span>
          {e.exploitable && <span className="text-[10px] font-semibold" style={{ color: "var(--color-sev-critical)" }}>EXPLOITABLE</span>}
        </div>
      );
    case "spawn":
      return wrap(
        <div className="text-[12px] text-[var(--color-muted)]">
          <span style={{ color: "var(--color-accent)" }}>spawned</span> {ROLE_LABEL[e.role] || e.role} — {e.task}
        </div>
      );
    case "status":
    case "finish":
      return wrap(
        <div className="text-[11px] uppercase tracking-wide text-[var(--color-faint)]">
          {e.type === "finish" ? `finished — ${e.summary}` : e.status}
        </div>
      );
    default:
      return null;
  }
}

function argStr(args) {
  if (!args || typeof args !== "object") return "";
  return Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
}
function label(id) {
  return { a0001: "Coordinator", a0002: "Recon", a0003: "Exploitation" }[id] || id;
}
function outcomeColor(o) {
  if (/exploit|true_positive|finding/i.test(o)) return "var(--color-ok)";
  if (/false|reject|drop/i.test(o)) return "var(--color-sev-high)";
  return "var(--color-ink)";
}

/* ---- legacy fallback for runs captured before the transcript existed ---- */
function LegacyTrajectory({ node }) {
  const traj = node.trajectory || [];
  if (!traj.length) return <p className="mt-3 text-[13px] text-[var(--color-faint)]">No recorded steps.</p>;
  return (
    <ol className="mt-3 space-y-2">
      {traj.map((ev, i) => (
        <li key={i} className="text-[13px]">
          <span className="font-medium text-[var(--color-ink)]">{ev.label}</span>
          {ev.detail && <div className="text-[12px] text-[var(--color-muted)]">{ev.detail}</div>}
        </li>
      ))}
    </ol>
  );
}

/* ---- graph (unchanged computed-coordinate layout) ----------------------- */

function AgentGraph({ root, children, selectedId, onSelect }) {
  const NODE_W = 184;
  const ROOT_Y = 10;
  const NODE_H = 60;
  const BUS_Y = ROOT_Y + NODE_H + 26;
  const CHILD_Y = BUS_Y + 26;
  const HEIGHT = CHILD_Y + NODE_H + 10;

  const n = Math.max(children.length, 1);
  const xPct = (i) => ((i + 0.5) / n) * 100;
  const rootX = 50;
  const xFirst = children.length ? xPct(0) : rootX;
  const xLast = children.length ? xPct(children.length - 1) : rootX;

  return (
    <div className="overflow-x-auto pb-1">
      <div className="relative mx-auto" style={{ height: HEIGHT, minWidth: n * (NODE_W + 24) }}>
        <svg className="absolute inset-0 h-full w-full" aria-hidden>
          {children.length > 0 && (
            <line x1={`${rootX}%`} y1={ROOT_Y + NODE_H} x2={`${rootX}%`} y2={BUS_Y}
                  stroke="var(--color-border-strong)" strokeWidth="1.5" />
          )}
          {children.length > 1 && (
            <line x1={`${xFirst}%`} y1={BUS_Y} x2={`${xLast}%`} y2={BUS_Y}
                  stroke="var(--color-border-strong)" strokeWidth="1.5" />
          )}
          {children.map((c, i) => (
            <line key={c.id} x1={`${xPct(i)}%`} y1={BUS_Y} x2={`${xPct(i)}%`} y2={CHILD_Y}
                  stroke="var(--color-border-strong)" strokeWidth="1.5" />
          ))}
        </svg>
        <GraphNode node={root} x={rootX} y={ROOT_Y} w={NODE_W} root
                   selected={selectedId === root.id} onSelect={onSelect} />
        {children.map((c, i) => (
          <GraphNode key={c.id} node={c} x={xPct(i)} y={CHILD_Y} w={NODE_W}
                     selected={selectedId === c.id} onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}

function GraphNode({ node, x, y, w, root, selected, onSelect }) {
  const color = statusColor(node.status);
  return (
    <button
      onClick={() => onSelect(node.id)}
      aria-pressed={selected}
      className="lift absolute rounded-xl border bg-[var(--color-surface-2)] px-3 py-2 text-left"
      style={{
        left: `${x}%`, top: y, width: w, transform: "translateX(-50%)",
        borderColor: selected ? "var(--color-accent)"
          : root ? "color-mix(in oklab, var(--color-accent) 40%, transparent)"
          : "var(--color-border-strong)",
        boxShadow: selected ? "0 0 0 1px var(--color-accent)" : undefined,
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[13px] font-semibold"
              style={root ? { color: "var(--color-accent)" } : undefined}>
          {ROLE_LABEL[node.role] || node.role}
        </span>
        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color }} title={node.status} />
      </div>
      <div className="mt-0.5 truncate text-[11px] text-[var(--color-faint)]" title={node.task}>{node.task}</div>
      <div className="mt-1.5 flex items-center gap-1.5">
        <StepMeter steps={node.steps_spent} />
        <span className="font-mono text-[10px] text-[var(--color-faint)] tabular-nums">
          {node.steps_spent} step{node.steps_spent === 1 ? "" : "s"}
        </span>
      </div>
    </button>
  );
}

function StepMeter({ steps }) {
  const cells = 6;
  const filled = Math.min(cells, steps);
  return (
    <span className="flex items-center gap-0.5" aria-hidden>
      {Array.from({ length: cells }).map((_, i) => (
        <span key={i} className="h-2.5 w-1 rounded-[1px]"
              style={{ background: i < filled ? "var(--color-accent)" : "var(--color-border-strong)" }} />
      ))}
    </span>
  );
}
