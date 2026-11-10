// Authored line-icon set — one consistent 24-grid, 1.75 stroke, currentColor.
// No Unicode glyphs or emoji stand-ins anywhere in the UI.

function Svg({ children, size = 16, ...rest }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

export function IconOverview(p) {
  return (
    <Svg {...p}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </Svg>
  );
}

export function IconFindings(p) {
  // target / scope — a confirmed finding
  return (
    <Svg {...p}>
      <circle cx="11" cy="11" r="7" />
      <circle cx="11" cy="11" r="2.5" />
      <path d="M11 2v3M11 17v3M2 11h3M17 11h3" />
    </Svg>
  );
}

export function IconAgents(p) {
  // graph of nodes
  return (
    <Svg {...p}>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="18" r="2.5" />
      <circle cx="19" cy="18" r="2.5" />
      <path d="M11 7.2 6.4 15.6M13 7.2 17.6 15.6" />
    </Svg>
  );
}

export function IconHypotheses(p) {
  // beaker — the hypothesis engine
  return (
    <Svg {...p}>
      <path d="M9 3h6M10 3v6l-5 8.5A2 2 0 0 0 6.8 21h10.4a2 2 0 0 0 1.8-3.5L14 9V3" />
      <path d="M7.5 15h9" />
    </Svg>
  );
}

export function IconDecisions(p) {
  // branching decision
  return (
    <Svg {...p}>
      <circle cx="6" cy="5" r="2.5" />
      <circle cx="6" cy="19" r="2.5" />
      <circle cx="18" cy="12" r="2.5" />
      <path d="M6 7.5v9M8.3 5.8 15.6 11M8.3 18.2 15.6 13" />
    </Svg>
  );
}

export function IconTools(p) {
  // wrench
  return (
    <Svg {...p}>
      <path d="M15.5 3.5a5 5 0 0 0-5.7 6.4L3.5 16.2a2.1 2.1 0 0 0 3 3l6.3-6.3a5 5 0 0 0 6.4-5.7l-2.9 2.9-2.8-.7-.7-2.8 2.9-2.9Z" />
    </Svg>
  );
}

export function IconShield(p) {
  return (
    <Svg {...p}>
      <path d="M12 3 5 6v5c0 4.2 2.9 7.8 7 9 4.1-1.2 7-4.8 7-9V6l-7-3Z" />
      <path d="m9 11.5 2 2 4-4.5" />
    </Svg>
  );
}

// Small solid engine markers (10px): diamond = dynamic, stacked = static.
export function MarkDynamic({ size = 9 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" aria-hidden="true">
      <path d="M5 0.5 9.5 5 5 9.5 0.5 5Z" fill="currentColor" />
    </svg>
  );
}

export function MarkStatic({ size = 9 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" aria-hidden="true">
      <rect x="0.75" y="1.25" width="8.5" height="2.4" rx="0.6" fill="currentColor" />
      <rect x="0.75" y="4.3" width="8.5" height="2.4" rx="0.6" fill="currentColor" opacity="0.65" />
      <rect x="0.75" y="7.35" width="8.5" height="2.4" rx="0.6" fill="currentColor" opacity="0.4" />
    </svg>
  );
}

export const NAV_ICONS = {
  overview: IconOverview,
  findings: IconFindings,
  agents: IconAgents,
  hypotheses: IconHypotheses,
  decisions: IconDecisions,
  tools: IconTools,
};
