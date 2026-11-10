import { useMemo, useState } from "react";
import { ReactFlow, Background, Controls, Handle, Position } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import { Panel, Tag } from "../lib/ui.jsx";
import { useLiveEvents, agentsFromEvents } from "../lib/data.js";

const ROLE_LABEL = {
  coordinator: "Coordinator",
  recon: "Recon",
  exploitation: "Exploitation",
  post_exploitation: "Post-exploitation",
  researcher: "Researcher",
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
  // Build the graph from the unified transcript (both engines' agents) when it
  // carries spawn events; else fall back to the dynamic engine's snapshot.
  const graph = useMemo(() => {
    if (transcript.some((e) => e.type === "spawn")) return agentsFromEvents(transcript);
    return model.graph || [];
  }, [transcript, model.graph]);

  const roots = graph.filter((n) => !n.parent_id);

  const [picked, setSelectedId] = useState(null);
  const selectedId = picked ?? roots[0]?.id ?? null;
  const roleOf = useMemo(
    () => Object.fromEntries(graph.map((n) => [n.id, n.role])),
    [graph]
  );
  const selected = graph.find((n) => n.id === selectedId) || null;
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
          <AgentFlow graph={graph} selectedId={selectedId} onSelect={setSelectedId} />
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
  return { a0001: "Coordinator", a0002: "Recon", a0003: "Exploitation", s0001: "Researcher" }[id] || id;
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

/* ---- graph (React Flow + dagre hierarchical auto-layout) ---------------- */

const NODE_W = 196;
const NODE_H = 72;
const nodeTypes = { agent: AgentFlowNode };

function layout(agents) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", nodesep: 36, ranksep: 56, marginx: 8, marginy: 8 });
  g.setDefaultEdgeLabel(() => ({}));
  agents.forEach((a) => g.setNode(a.id, { width: NODE_W, height: NODE_H }));
  const edges = [];
  agents.forEach((a) => {
    if (a.parent_id && agents.some((n) => n.id === a.parent_id)) {
      g.setEdge(a.parent_id, a.id);
      edges.push({
        id: `${a.parent_id}-${a.id}`, source: a.parent_id, target: a.id,
        type: "smoothstep", animated: a.status === "running",
        style: { stroke: "var(--color-border-strong)", strokeWidth: 1.5 },
      });
    }
  });
  dagre.layout(g);
  const nodes = agents.map((a) => {
    const p = g.node(a.id);
    return {
      id: a.id, type: "agent", data: a,
      position: { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 },
      draggable: false,
    };
  });
  return { nodes, edges };
}

function AgentFlow({ graph, selectedId, onSelect }) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph]);
  // inject selection state into node data (so the custom node can style itself)
  const rfNodes = useMemo(
    () => nodes.map((n) => ({ ...n, data: { ...n.data, selected: n.id === selectedId },
                              selected: n.id === selectedId })),
    [nodes, selectedId]
  );
  return (
    <div style={{ height: 340 }} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]">
      <ReactFlow
        nodes={rfNodes}
        edges={edges}
        nodeTypes={nodeTypes}
        colorMode="dark"
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.4}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        onNodeClick={(_, n) => onSelect(n.id)}
        style={{ background: "transparent" }}
      >
        <Background color="var(--color-border)" gap={20} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function AgentFlowNode({ data }) {
  const { role, task, status, steps_spent, selected } = data;
  const root = !data.parent_id;
  const color = statusColor(status);
  return (
    <div
      className="rounded-xl border bg-[var(--color-surface-2)] px-3 py-2 text-left"
      style={{
        width: NODE_W, height: NODE_H,
        borderColor: selected ? "var(--color-accent)"
          : root ? "color-mix(in oklab, var(--color-accent) 40%, transparent)"
          : "var(--color-border-strong)",
        boxShadow: selected ? "0 0 0 1px var(--color-accent)" : "none",
        cursor: "pointer",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} isConnectable={false} />
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[13px] font-semibold"
              style={root ? { color: "var(--color-accent)" } : undefined}>
          {ROLE_LABEL[role] || role}
        </span>
        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color }} title={status} />
      </div>
      <div className="mt-0.5 truncate text-[11px] text-[var(--color-faint)]" title={task}>{task}</div>
      <div className="mt-1.5 flex items-center gap-1.5">
        <StepMeter steps={steps_spent} />
        <span className="font-mono text-[10px] text-[var(--color-faint)] tabular-nums">
          {steps_spent} step{steps_spent === 1 ? "" : "s"}
        </span>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} isConnectable={false} />
    </div>
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
