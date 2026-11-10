// Shared visual primitives — one system (tokens from index.css), used everywhere.

export const SEVERITY = {
  Critical: { color: "var(--color-sev-critical)", rank: 4 },
  High: { color: "var(--color-sev-high)", rank: 3 },
  Medium: { color: "var(--color-sev-medium)", rank: 2 },
  Low: { color: "var(--color-sev-low)", rank: 1 },
  None: { color: "var(--color-sev-none)", rank: 0 },
};
export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"];

export function sevColor(name) {
  return (SEVERITY[name] || SEVERITY.None).color;
}

export function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

export function Panel({ title, action, children, className }) {
  return (
    <section
      className={cx(
        "rounded-[var(--radius-card)] border border-[var(--color-border)]",
        "bg-[var(--color-surface)]",
        className
      )}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-[var(--color-border)] px-4 py-3">
          <h2 className="text-[13px] font-semibold tracking-wide text-[var(--color-muted)] uppercase">
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint, accent }) {
  return (
    <div className="lift rounded-[var(--radius-card)] border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="text-[12px] font-medium uppercase tracking-wide text-[var(--color-faint)]">
        {label}
      </div>
      <div
        className="mt-1 text-3xl font-semibold tabular-nums"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
      {hint && <div className="mt-1 text-[13px] text-[var(--color-muted)]">{hint}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }) {
  const color = sevColor(severity);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[12px] font-medium"
      style={{
        color,
        borderColor: color + "55",
        background: color + "14",
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {severity}
    </span>
  );
}

export function Tag({ children, tone = "muted", title }) {
  const tones = {
    muted: "text-[var(--color-muted)] border-[var(--color-border-strong)]",
    accent: "text-[var(--color-accent)] border-[color-mix(in_oklab,var(--color-accent)_45%,transparent)]",
    ok: "text-[var(--color-ok)] border-[color-mix(in_oklab,var(--color-ok)_45%,transparent)]",
  };
  return (
    <span
      title={title}
      className={cx(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
        tones[tone] || tones.muted
      )}
    >
      {children}
    </span>
  );
}

export function EngineTag({ engine }) {
  const icon = engine === "dynamic" ? "◆" : "▣";
  return (
    <Tag tone="accent" title={`${engine} engine`}>
      <span aria-hidden>{icon}</span>
      {engine}
    </Tag>
  );
}

/** Accessible SVG donut of severity counts. */
export function SeverityDonut({ counts, size = 168, stroke = 18 }) {
  const entries = SEVERITY_ORDER.map((s) => [s, counts[s] || 0]).filter(([, n]) => n > 0);
  const total = entries.reduce((a, [, n]) => a + n, 0);
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="flex items-center gap-5">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
           aria-label={`Findings by severity, ${total} total`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
                stroke="var(--color-border)" strokeWidth={stroke} />
        {entries.map(([s, n]) => {
          const frac = n / total;
          const dash = frac * c;
          const el = (
            <circle key={s} cx={size / 2} cy={size / 2} r={r} fill="none"
                    stroke={sevColor(s)} strokeWidth={stroke}
                    strokeDasharray={`${dash} ${c - dash}`}
                    strokeDashoffset={-offset}
                    transform={`rotate(-90 ${size / 2} ${size / 2})`}
                    strokeLinecap="butt" />
          );
          offset += dash;
          return el;
        })}
        <text x="50%" y="48%" textAnchor="middle" className="fill-[var(--color-ink)]"
              style={{ fontSize: 30, fontWeight: 650 }}>{total}</text>
        <text x="50%" y="62%" textAnchor="middle" className="fill-[var(--color-faint)]"
              style={{ fontSize: 11, letterSpacing: 1 }}>FINDINGS</text>
      </svg>
      <ul className="space-y-1.5 text-[13px]">
        {SEVERITY_ORDER.map((s) => (
          <li key={s} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: sevColor(s) }} />
            <span className="w-16 text-[var(--color-muted)]">{s}</span>
            <span className="tabular-nums font-medium">{counts[s] || 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Horizontal labelled bars (OWASP, engines, etc). */
export function BarList({ items, color = "var(--color-accent)" }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-2.5">
      {items.map((i) => (
        <li key={i.label}>
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[13px]">
            <span className="truncate text-[var(--color-muted)]" title={i.label}>{i.label}</span>
            <span className="tabular-nums font-medium">{i.value}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-[var(--color-surface-2)]">
            <div className="grow h-full rounded-full"
                 style={{ width: `${(i.value / max) * 100}%`, background: i.color || color }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
