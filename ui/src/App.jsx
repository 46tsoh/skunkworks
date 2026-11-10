import { useState } from "react";
import { useAegisData, deriveModel } from "./lib/data.js";
import { cx } from "./lib/ui.jsx";
import { NAV_ICONS, IconShield } from "./lib/icons.jsx";
import Overview from "./views/Overview.jsx";
import Findings from "./views/Findings.jsx";
import Agents from "./views/Agents.jsx";
import Hypotheses from "./views/Hypotheses.jsx";
import Decisions from "./views/Decisions.jsx";
import Tools from "./views/Tools.jsx";

const NAV = [
  ["overview", "Overview"],
  ["findings", "Findings"],
  ["agents", "Agent graph"],
  ["hypotheses", "Hypotheses"],
  ["decisions", "Decisions"],
  ["tools", "Tools"],
];

export default function App() {
  const { loading, error, report, decisions } = useAegisData();
  const [tab, setTab] = useState("overview");
  const [findingId, setFindingId] = useState(null);

  const model = report ? deriveModel(report, decisions) : null;

  const openFinding = (id) => { setFindingId(id); setTab("findings"); };

  return (
    <div className="flex min-h-screen">
      {/* sidebar */}
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)]/70 px-3 py-4 backdrop-blur md:flex">
        <div className="flex items-center gap-2 px-2 pb-5">
          <span className="grid h-8 w-8 place-items-center rounded-lg text-[var(--color-accent-ink)]"
                style={{ background: "var(--color-accent)" }}>
            <IconShield size={18} />
          </span>
          <div>
            <div className="text-[15px] font-semibold leading-none">Aegis</div>
            <div className="text-[11px] text-[var(--color-faint)]">security dashboard</div>
          </div>
        </div>
        <nav className="flex flex-col gap-0.5">
          {NAV.map(([id, label]) => {
            const Icon = NAV_ICONS[id];
            const active = tab === id;
            return (
              <button key={id} onClick={() => setTab(id)}
                className={cx("tap flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[14px]",
                  active ? "bg-[var(--color-surface-2)] text-[var(--color-ink)]"
                         : "text-[var(--color-muted)] hover:bg-[var(--color-surface-2)]/50")}>
                <span className="grid h-4 w-4 place-items-center"
                      style={{ color: active ? "var(--color-accent)" : "var(--color-faint)" }}>
                  <Icon size={16} />
                </span>
                {label}
              </button>
            );
          })}
        </nav>
        <div className="mt-auto px-2 text-[11px] leading-relaxed text-[var(--color-faint)]">
          local-only · no telemetry
        </div>
      </aside>

      {/* main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center gap-4 border-b border-[var(--color-border)] bg-[var(--color-bg)]/80 px-5 py-3 backdrop-blur">
          <h1 className="text-[15px] font-semibold">
            {NAV.find(([id]) => id === tab)?.[1]}
          </h1>
          {model && (
            <div className="ml-auto flex items-center gap-3 text-[12px] text-[var(--color-muted)]">
              <span className="font-mono">{model.run.run_id}</span>
              <span className="hidden sm:inline">· backend {model.run.backend}</span>
              {model.metrics.degraded
                ? <span className="rounded-full px-2 py-0.5 font-medium"
                        style={{ color: "var(--color-sev-high)", background: "color-mix(in oklab, var(--color-sev-high) 15%, transparent)" }}>degraded</span>
                : <span className="rounded-full px-2 py-0.5 font-medium"
                        style={{ color: "var(--color-ok)", background: "color-mix(in oklab, var(--color-ok) 15%, transparent)" }}>complete</span>}
            </div>
          )}
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-5 py-6">
          {loading && <Centered>Loading run…</Centered>}
          {error && (
            <Centered>
              <div className="max-w-md text-center">
                <p className="text-[var(--color-sev-high)]">Could not load run data.</p>
                <p className="mt-2 text-[13px] text-[var(--color-muted)]">{error}</p>
                <p className="mt-3 font-mono text-[12px] text-[var(--color-faint)]">
                  aegis run --out ui/public/data
                </p>
              </div>
            </Centered>
          )}
          {model && (
            <div key={tab} className="enter">
              {tab === "overview" && <Overview model={model} onOpenFinding={openFinding} goto={setTab} />}
              {tab === "findings" && <Findings model={model} selectedId={findingId} onSelect={setFindingId} />}
              {tab === "agents" && <Agents model={model} />}
              {tab === "hypotheses" && <Hypotheses model={model} />}
              {tab === "decisions" && <Decisions model={model} />}
              {tab === "tools" && <Tools model={model} />}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function Centered({ children }) {
  return <div className="grid min-h-[50vh] place-items-center text-[var(--color-muted)]">{children}</div>;
}
