// Red Team view — surfaces `aegis exploit` results (stage 1 exploit->verify,
// stage 2 post-exploit, stage 3 lateral) for an operator to read at a glance.
//
// Why a dedicated view: the exploit engine is scope-gated and deliberately
// stops at proof, so the interesting signal is not "how many findings" but
// "what was confirmed, with what evidence, and — crucially — what the engine
// SAW but refused to touch". The lateral section leans into that: out-of-scope
// hosts are rendered as "seen, refused, never touched", never as targets.
//
// Every string here is treated as already-sanitised (the CLI runs it through
// aegis.redteam.http.sanitize_text before writing --out), but we still render
// it as plain JSX text — never dangerouslySetInnerHTML — so a hostile byte that
// slipped through is shown, not interpreted.
import { useRedTeamData } from "../lib/data.js";
import { Panel, Tag, cx } from "../lib/ui.jsx";

const GEN_CMD =
  "aegis exploit --type cmdi --target <url> --param <p> --scope <engagement> " +
  "--authorized --out ui/public/data/redteam.json";

export default function RedTeam() {
  const { loading, data, source } = useRedTeamData();

  if (loading) {
    return <div className="grid min-h-[40vh] place-items-center text-[var(--color-muted)]">Loading red-team result…</div>;
  }
  if (!data || !data.result) return <EmptyState />;

  const r = data.result;
  const pe = r.post_exploit;
  const lat = r.lateral;

  return (
    <div className="space-y-5">
      {source === "sample" && (
        <div className="rounded-[var(--radius-card)] border border-[color-mix(in_oklab,var(--color-accent)_45%,transparent)] bg-[color-mix(in_oklab,var(--color-accent)_10%,transparent)] px-4 py-2.5 text-[13px] text-[var(--color-muted)]">
          Showing bundled <span className="font-mono">redteam.sample.json</span>. Generate a real result with{" "}
          <code className="font-mono text-[12px]">aegis exploit … --out ui/public/data/redteam.json</code>.
        </div>
      )}

      <ResultHeader r={r} engagement={data.engagement} />
      <ProofPanel r={r} />
      <PostExploitPanel pe={pe} />
      <LateralPanel lat={lat} />
    </div>
  );
}

// ---------------------------------------------------------------------------

function StatusPill({ on, labelOn, labelOff, tone = "ok" }) {
  const color = on
    ? tone === "crit"
      ? "var(--color-sev-critical)"
      : "var(--color-ok)"
    : "var(--color-faint)";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[12px] font-medium"
      style={{ color, borderColor: color + "55", background: color + "14" }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {on ? labelOn : labelOff}
    </span>
  );
}

function ResultHeader({ r, engagement }) {
  return (
    <Panel title="Exploit target">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-[var(--color-surface-2)] px-2 py-0.5 font-mono text-[12px] font-semibold uppercase tracking-wide text-[var(--color-accent)]">
              {r.kind || "?"}
            </span>
            {r.technique && <Tag>technique {r.technique}</Tag>}
            {r.cwe && <Tag>{r.cwe}</Tag>}
          </div>
          <h3 className="mt-2 font-mono text-[15px] font-semibold break-all">{r.target || "—"}</h3>
          <dl className="mt-2 grid grid-cols-[88px_1fr] gap-y-1.5 text-[13px]">
            <dt className="text-[var(--color-faint)]">param</dt>
            <dd className="font-mono text-[12px] break-all">{r.param || "—"}</dd>
            <dt className="text-[var(--color-faint)]">engagement</dt>
            <dd className="break-all">{engagement || "unnamed"}</dd>
            <dt className="text-[var(--color-faint)]">requests</dt>
            <dd className="tabular-nums">{r.requests ?? 0}</dd>
          </dl>
        </div>
        <div className="flex flex-col items-start gap-1.5">
          <StatusPill on={r.in_scope} labelOn="in scope" labelOff="out of scope" tone={r.in_scope ? "ok" : "crit"} />
          <StatusPill on={r.attempted} labelOn="attempted" labelOff="not attempted" />
          <StatusPill on={r.verified} labelOn="verified" labelOff="not confirmed" tone="crit" />
        </div>
      </div>
      {r.note && (
        <p className="mt-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-[12px] leading-relaxed text-[var(--color-muted)]">
          {r.note}
        </p>
      )}
    </Panel>
  );
}

function ProofPanel({ r }) {
  const evidence = r.evidence || [];
  return (
    <Panel title="Proof & evidence">
      {r.proof ? (
        <div className="rounded-lg border px-3 py-2.5"
             style={{ borderColor: "color-mix(in oklab, var(--color-sev-critical) 45%, transparent)",
                      background: "color-mix(in oklab, var(--color-sev-critical) 10%, transparent)" }}>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide"
               style={{ color: "var(--color-sev-critical)" }}>proof</div>
          <p className="text-[13px] leading-relaxed text-[var(--color-ink)] break-words">{r.proof}</p>
        </div>
      ) : (
        <p className="text-[13px] text-[var(--color-faint)]">No proof recorded.</p>
      )}
      <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
        evidence ({evidence.length})
      </div>
      <ul className="mt-1.5 space-y-1.5 text-[13px] text-[var(--color-muted)]">
        {evidence.map((e, i) => (
          <li key={i} className="flex gap-2">
            <span className="text-[var(--color-faint)]">—</span>
            <span className="break-words">{e}</span>
          </li>
        ))}
        {evidence.length === 0 && <li className="text-[var(--color-faint)]">No evidence recorded.</li>}
      </ul>
    </Panel>
  );
}

function CmdMark({ ok }) {
  const color = ok ? "var(--color-ok)" : "var(--color-sev-high)";
  return (
    <span className="grid h-4 w-4 shrink-0 place-items-center rounded text-[10px] font-semibold"
          style={{ color, border: `1px solid ${color}66` }} title={ok ? "ok" : "failed"}>
      {ok ? "✓" : "✕"}
    </span>
  );
}

function PostExploitPanel({ pe }) {
  if (!pe || !pe.ran) {
    return (
      <Panel title="Post-exploit (stage 2)">
        <p className="text-[13px] text-[var(--color-faint)]">
          No post-exploit run. Stage 2 runs only on a confirmed <span className="font-mono">cmdi</span> foothold when the
          engagement scope sets <span className="font-mono">allow_post_exploit</span>.
        </p>
      </Panel>
    );
  }
  const commands = pe.commands || [];
  const filesRead = pe.files_read || [];
  return (
    <Panel title="Post-exploit (stage 2) — read-only proof">
      {pe.flag ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2.5"
             style={{ borderColor: "color-mix(in oklab, var(--color-ok) 45%, transparent)",
                      background: "color-mix(in oklab, var(--color-ok) 10%, transparent)" }}>
          <span className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--color-ok)" }}>flag</span>
          <code className="font-mono text-[13px] font-semibold break-all" style={{ color: "var(--color-ok)" }}>{pe.flag}</code>
          {pe.flag_path && <span className="font-mono text-[11px] text-[var(--color-faint)] break-all">{pe.flag_path}</span>}
        </div>
      ) : (
        <p className="text-[13px] text-[var(--color-muted)]">Foothold confirmed; no flag pattern matched.</p>
      )}

      <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
        commands ({commands.length})
      </div>
      <ul className="mt-1.5 space-y-1.5">
        {commands.map((c, i) => (
          <li key={i} className="flex items-start gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
            <CmdMark ok={c.ok} />
            <div className="min-w-0 flex-1">
              <div className="font-mono text-[12px] font-semibold break-all">{c.command}</div>
              {c.output && (
                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] text-[var(--color-muted)]">{c.output}</pre>
              )}
            </div>
          </li>
        ))}
        {commands.length === 0 && <li className="text-[13px] text-[var(--color-faint)]">No commands recorded.</li>}
      </ul>

      {filesRead.length > 0 && (
        <>
          <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
            files read ({filesRead.length}) — no flag pattern
          </div>
          <ul className="mt-1.5 space-y-1.5">
            {filesRead.map((f, i) => (
              <li key={i} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
                <div className="font-mono text-[12px] font-semibold break-all">{f.path}</div>
                {f.content && (
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] text-[var(--color-muted)]">{f.content}</pre>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      <EvidenceFooter evidence={pe.evidence} requests={pe.requests} note={pe.note} />
    </Panel>
  );
}

function LateralPanel({ lat }) {
  if (!lat || !lat.ran) {
    return (
      <Panel title="Lateral movement (stage 3)">
        <p className="text-[13px] text-[var(--color-faint)]">
          No lateral movement run. Stage 3 runs only when the engagement scope sets{" "}
          <span className="font-mono">allow_lateral</span>, and acts on in-scope hosts only.
        </p>
      </Panel>
    );
  }
  const refused = lat.refused_out_of_scope || [];
  const pivots = lat.pivots || [];
  const capped = lat.capped || [];
  const discovered = lat.discovered || [];

  return (
    <Panel title="Lateral movement (stage 3) — in-scope only, read-only">
      {refused.length > 0 && (
        <div className="rounded-lg border px-3 py-2.5"
             style={{ borderColor: "color-mix(in oklab, var(--color-sev-high) 45%, transparent)",
                      background: "color-mix(in oklab, var(--color-sev-high) 10%, transparent)" }}>
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--color-sev-high)" }}>
            seen · refused · never touched ({refused.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {refused.map((h, i) => (
              <span key={i} className="rounded-md border px-2 py-0.5 font-mono text-[12px]"
                    style={{ color: "var(--color-sev-high)",
                             borderColor: "color-mix(in oklab, var(--color-sev-high) 45%, transparent)" }}>
                {h}
              </span>
            ))}
          </div>
          <p className="mt-1.5 text-[11px] text-[var(--color-faint)]">
            Out of scope — discovered by recon but never probed or acted on.
          </p>
        </div>
      )}

      <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
        in-scope pivots ({pivots.length})
      </div>
      <ul className="mt-1.5 space-y-1.5">
        {pivots.map((p, i) => (
          <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
            <StatusPill on={p.reachable} labelOn="reachable" labelOff="no response" />
            <span className="min-w-0 flex-1 font-mono text-[12px] break-all">{p.url || p.host}</span>
            {p.flag && (
              <code className="font-mono text-[12px] font-semibold break-all" style={{ color: "var(--color-ok)" }}>
                {p.flag}
              </code>
            )}
            {p.detail && <span className="w-full text-[11px] text-[var(--color-faint)] break-words">{p.detail}</span>}
          </li>
        ))}
        {pivots.length === 0 && <li className="text-[13px] text-[var(--color-faint)]">No in-scope pivots acted on.</li>}
      </ul>

      {capped.length > 0 && (
        <p className="mt-3 text-[12px] text-[var(--color-muted)]">
          <span className="font-semibold text-[var(--color-faint)]">capped (max_hosts): </span>
          <span className="font-mono">{capped.join(", ")}</span>
        </p>
      )}

      {discovered.length > 0 && (
        <p className="mt-2 text-[11px] text-[var(--color-faint)]">
          <span className="uppercase tracking-wide">discovered: </span>
          <span className="font-mono">{discovered.join(", ")}</span>
        </p>
      )}

      <EvidenceFooter requests={lat.requests} note={lat.note} />
    </Panel>
  );
}

function EvidenceFooter({ evidence = [], requests, note }) {
  const hasEvidence = evidence.length > 0;
  if (!hasEvidence && !note && requests == null) return null;
  return (
    <div className="mt-3 border-t border-[var(--color-border)] pt-2.5 text-[12px] text-[var(--color-muted)]">
      {hasEvidence && (
        <ul className="space-y-1">
          {evidence.map((e, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-[var(--color-faint)]">—</span>
              <span className="break-words">{e}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--color-faint)]">
        {requests != null && <span>requests: <span className="tabular-nums">{requests}</span></span>}
        {note && <span className="break-words">{note}</span>}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <Panel title="Red team">
      <div className="max-w-xl space-y-3 text-[13px] leading-relaxed text-[var(--color-muted)]">
        <p>
          No red-team result loaded. This view reads <span className="font-mono">data/redteam.json</span> — the file written
          by <span className="font-mono">aegis exploit --out</span> — and falls back to the bundled{" "}
          <span className="font-mono">data/redteam.sample.json</span> demo when none exists.
        </p>
        <p>Generate a real one (scope-gated, non-destructive) and drop it next to the other dashboard data:</p>
        <pre className="overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5 font-mono text-[12px] text-[var(--color-ink)]">{GEN_CMD}</pre>
        <p className="text-[12px] text-[var(--color-faint)]">
          Stages 2 (post-exploit) and 3 (lateral) appear only when the engagement scope opts into them.
        </p>
      </div>
    </Panel>
  );
}
