import { useMemo, useState } from "react";
import { Panel, SeverityBadge, EngineTag, Tag, SEVERITY, cx } from "../lib/ui.jsx";

const CVSS_METRICS = {
  AV: { label: "Attack Vector", vals: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { label: "Attack Complexity", vals: { L: "Low", H: "High" } },
  PR: { label: "Privileges Req.", vals: { N: "None", L: "Low", H: "High" } },
  UI: { label: "User Interaction", vals: { N: "None", R: "Required" } },
  S: { label: "Scope", vals: { U: "Unchanged", C: "Changed" } },
  C: { label: "Confidentiality", vals: { N: "None", L: "Low", H: "High" } },
  I: { label: "Integrity", vals: { N: "None", L: "Low", H: "High" } },
  A: { label: "Availability", vals: { N: "None", L: "Low", H: "High" } },
};

function parseVector(v) {
  return v.split("/").reduce((acc, part) => {
    const [k, val] = part.split(":");
    if (CVSS_METRICS[k]) acc[k] = val;
    return acc;
  }, {});
}

const STAGES = [
  "reachable from an external entry point",
  "attacker-controlled input reaches it",
  "path constraints satisfiable",
  "sink genuinely dangerous",
  "no effective sanitizer on the path",
  "exploitation primitive achievable",
  "impact material",
  "proof-of-concept plausible",
];

export default function Findings({ model, selectedId, onSelect }) {
  const { accepted } = model;
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [eng, setEng] = useState("all");
  const [exploitOnly, setExploitOnly] = useState(false);
  const [sort, setSort] = useState({ key: "cvss_score", dir: -1 });

  const rows = useMemo(() => {
    let r = accepted.filter((f) => {
      if (sev !== "all" && f.severity !== sev) return false;
      if (eng !== "all" && f.source_engine !== eng) return false;
      if (exploitOnly && !f.exploitable) return false;
      if (q && !(`${f.title} ${f.cwe} ${f.component} ${f.owasp || ""}`.toLowerCase().includes(q.toLowerCase())))
        return false;
      return true;
    });
    const { key, dir } = sort;
    r = [...r].sort((a, b) => {
      let av = a[key], bv = b[key];
      if (key === "severity") { av = SEVERITY[a.severity].rank; bv = SEVERITY[b.severity].rank; }
      if (typeof av === "string") return dir * av.localeCompare(bv);
      return dir * ((av ?? 0) - (bv ?? 0));
    });
    return r;
  }, [accepted, q, sev, eng, exploitOnly, sort]);

  const selected = accepted.find((f) => f.id === selectedId) || null;
  const engines = [...new Set(accepted.map((f) => f.source_engine))];

  const th = (key, label, align = "left") => (
    <th className={cx("cursor-pointer select-none px-3 py-2 font-medium text-[var(--color-faint)]",
                      align === "right" ? "text-right" : "text-left")}
        onClick={() => setSort((s) => ({ key, dir: s.key === key ? -s.dir : -1 }))}>
      {label}{sort.key === key ? (sort.dir < 0 ? " ↓" : " ↑") : ""}
    </th>
  );

  return (
    <div className={cx("grid gap-5", selected ? "lg:grid-cols-[1fr_380px]" : "grid-cols-1")}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, CWE, component…"
            className="min-w-56 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-[14px] placeholder:text-[var(--color-faint)] focus:border-[var(--color-accent)] focus:outline-none" />
          <Select value={sev} onChange={setSev}
            options={[["all", "All severities"], ["Critical","Critical"],["High","High"],["Medium","Medium"],["Low","Low"],["None","None"]]} />
          <Select value={eng} onChange={setEng}
            options={[["all", "All engines"], ...engines.map((e) => [e, e])]} />
          <button onClick={() => setExploitOnly((v) => !v)}
            className={cx("tap rounded-lg border px-3 py-2 text-[13px] font-medium",
              exploitOnly ? "border-[var(--color-sev-critical)] text-[var(--color-sev-critical)] bg-[var(--color-sev-critical)]/10"
                          : "border-[var(--color-border)] text-[var(--color-muted)]")}>
            Exploitable
          </button>
        </div>

        <Panel title={`${rows.length} finding${rows.length === 1 ? "" : "s"}`}>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[14px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[12px] uppercase tracking-wide">
                  {th("cvss_score", "CVSS", "right")}
                  {th("severity", "Severity")}
                  {th("title", "Finding")}
                  {th("source_engine", "Engine")}
                  {th("posterior", "Post.", "right")}
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id} onClick={() => onSelect(f.id)}
                      className={cx("cursor-pointer border-b border-[var(--color-border)]/60 hover:bg-[var(--color-surface-2)]/60",
                        selectedId === f.id && "bg-[var(--color-surface-2)]")}>
                    <td className="px-3 py-2.5 text-right font-semibold tabular-nums"
                        style={{ color: SEVERITY[f.severity].color }}>{f.cvss_score.toFixed(1)}</td>
                    <td className="px-3 py-2.5"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate">{f.title}</span>
                        {f.exploitable && <Tag tone="accent" title="validated exploitable">exploit</Tag>}
                      </div>
                      <div className="text-[12px] text-[var(--color-faint)]">{f.cwe} · {f.component}</div>
                    </td>
                    <td className="px-3 py-2.5"><EngineTag engine={f.source_engine} /></td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-[var(--color-muted)]">
                      {f.posterior.toFixed(2)}</td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr><td colSpan={5} className="px-3 py-8 text-center text-[var(--color-muted)]">
                    No findings match these filters.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      {selected && <Detail f={selected} decisions={model.decisions} onClose={() => onSelect(null)} />}
    </div>
  );
}

function Select({ value, onChange, options }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-[13px] text-[var(--color-ink)] focus:border-[var(--color-accent)] focus:outline-none">
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}

function Detail({ f, decisions, onClose }) {
  const vec = parseVector(f.cvss_vector);
  const passed = f.stages_passed ?? 0;
  const related = (decisions || []).filter(
    (d) => d.inputs && JSON.stringify(d.inputs).includes(`[ref=${f.id}`)
  );
  return (
    <aside className="enter space-y-4 lg:sticky lg:top-4 lg:self-start">
      <Panel
        title="Finding detail"
        action={<button onClick={onClose} className="tap text-[13px] text-[var(--color-muted)] hover:text-[var(--color-ink)]">close ✕</button>}>
        <div className="flex items-start gap-3">
          <div className="text-3xl font-semibold tabular-nums" style={{ color: SEVERITY[f.severity].color }}>
            {f.cvss_score.toFixed(1)}
          </div>
          <div>
            <h3 className="text-[15px] font-semibold leading-snug">{f.title}</h3>
            <div className="mt-1 flex flex-wrap gap-1.5">
              <SeverityBadge severity={f.severity} />
              <EngineTag engine={f.source_engine} />
              {f.owasp && <Tag>{f.owasp}</Tag>}
            </div>
          </div>
        </div>

        {f.rationale && (
          <div className="mt-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-accent)]">
              Analyst note
            </div>
            <p className="text-[13px] leading-relaxed text-[var(--color-muted)]">{f.rationale}</p>
          </div>
        )}

        <dl className="mt-4 grid grid-cols-[88px_1fr] gap-y-2 text-[13px]">
          <dt className="text-[var(--color-faint)]">CWE</dt><dd>{f.cwe}</dd>
          <dt className="text-[var(--color-faint)]">Component</dt>
          <dd className="font-mono text-[12px] break-all">{f.component}</dd>
          <dt className="text-[var(--color-faint)]">Posterior</dt><dd className="tabular-nums">{f.posterior.toFixed(2)}</dd>
          <dt className="text-[var(--color-faint)]">Vector</dt>
          <dd className="font-mono text-[12px] break-all">{f.cvss_vector}</dd>
        </dl>

        <div className="mt-3 grid grid-cols-4 gap-1.5">
          {Object.entries(vec).map(([k, v]) => (
            <div key={k} className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1.5"
                 title={CVSS_METRICS[k].label + ": " + (CVSS_METRICS[k].vals[v] || v)}>
              <div className="text-[10px] text-[var(--color-faint)]">{k}</div>
              <div className="text-[12px] font-medium">{v}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Exploitability chain">
        <div className="mb-2 text-[13px] text-[var(--color-muted)]">
          {f.exploitable ? <span style={{ color: "var(--color-sev-critical)" }}>All 8 stages passed — exploitable</span>
                         : <span>Stopped at stage {passed + 1} — informational</span>}
        </div>
        <ol className="space-y-1">
          {STAGES.map((s, i) => {
            const state = f.exploitable || i < passed ? "pass" : i === passed ? "fail" : "skip";
            const color = state === "pass" ? "var(--color-ok)" : state === "fail" ? "var(--color-sev-high)" : "var(--color-faint)";
            return (
              <li key={i} className="flex items-center gap-2 text-[12px]">
                <span className="grid h-4 w-4 place-items-center rounded-full text-[10px]"
                      style={{ color, border: `1px solid ${color}66` }}>
                  {state === "pass" ? "✓" : state === "fail" ? "✕" : "·"}
                </span>
                <span style={{ color: state === "skip" ? "var(--color-faint)" : "var(--color-muted)" }}>{s}</span>
              </li>
            );
          })}
        </ol>
      </Panel>

      <Panel title={`Evidence (${(f.evidence || []).length})`}>
        <ul className="space-y-1.5 text-[13px] text-[var(--color-muted)]">
          {(f.evidence || []).map((e, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-[var(--color-faint)]">—</span><span>{e}</span>
            </li>
          ))}
          {(f.evidence || []).length === 0 && <li className="text-[var(--color-faint)]">No evidence recorded.</li>}
        </ul>
      </Panel>

      {related.length > 0 && (
        <Panel title={`Decision trail (${related.length})`}>
          <ul className="space-y-1.5 text-[12px]">
            {related.map((d, i) => (
              <li key={i} className="flex items-center justify-between gap-2">
                <span className="font-mono text-[var(--color-muted)]">{d.kind}</span>
                <span className="tabular-nums text-[var(--color-faint)]">
                  {d.probability != null ? `p=${d.probability.toFixed(2)}` : d.outcome?.value?.toFixed?.(2) ?? ""}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </aside>
  );
}
