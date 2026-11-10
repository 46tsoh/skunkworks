import { Panel, Tag, cx } from "../lib/ui.jsx";

// Capability catalog — the 17 adapters behind the common Tool interface.
const CATALOG = {
  static: [
    ["semgrep", "SAST rule matches over source"],
    ["codeql", "dataflow queries + SMT path-feasibility"],
    ["sca", "vulnerable/outdated dependencies, SBOM"],
    ["binary", "binary hardening + unsafe imports"],
    ["fuzz", "AFL++ crashing inputs"],
    ["crash", "crash/core triage + exploitability"],
    ["forensics", "git-history secret mining (gitleaks)"],
  ],
  dynamic: [
    ["recon", "local surface map (nmap)"],
    ["web", "per-endpoint testing (nuclei)"],
    ["dast", "active probes (ZAP)"],
    ["proxy", "intercepted-traffic issues (mitmproxy)"],
    ["browser", "DOM/client-side issues (headless chrome)"],
    ["shell", "scripted scanner CLI"],
    ["sandbox", "resource-capped validation script"],
    ["poc", "proof-of-concept generation"],
    ["frida", "runtime instrumentation hooks"],
    ["rr", "record-replay analysis"],
  ],
};

export default function Tools({ model }) {
  const runs = Object.fromEntries((model.toolRuns || []).map((t) => [t.name, t]));

  const section = (kind, items) => (
    <Panel title={`${kind} tools`} key={kind}>
      <div className="grid gap-2.5 sm:grid-cols-2">
        {items.map(([name, desc]) => {
          const run = runs[name];
          return (
            <div key={name} className="lift flex items-start justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[13px] font-semibold">{name}</span>
                  {run && <RunBadge status={run.status} count={run.candidates} />}
                </div>
                <p className="mt-0.5 truncate text-[12px] text-[var(--color-muted)]">{desc}</p>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );

  return (
    <div className="space-y-5">
      <Panel title="Tool adapters">
        <p className="text-[13px] text-[var(--color-muted)]">
          17 capabilities behind one <code className="font-mono">Tool</code> interface. Binary tools run in
          local containers (<code className="font-mono">--network none</code>, read-only mounts); each ships an
          offline fixture, so a run works with no images pulled. Run with
          <code className="font-mono"> aegis run --use-tools</code> to source candidates from them.
        </p>
      </Panel>
      {section("static", CATALOG.static)}
      {section("dynamic", CATALOG.dynamic)}
    </div>
  );
}

function RunBadge({ status, count }) {
  const ok = status === "ok";
  return (
    <span className={cx("rounded px-1.5 py-0.5 text-[10px] font-semibold")}
      style={{
        color: ok ? "var(--color-ok)" : "var(--color-sev-high)",
        background: (ok ? "var(--color-ok)" : "var(--color-sev-high)") + "18",
      }}>
      {ok ? `${count} cand.` : status}
    </span>
  );
}
