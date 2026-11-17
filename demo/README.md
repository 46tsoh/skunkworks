# demo/

Visual, self-contained demos of Aegis — what the tool is and how a run flows.
Local-only and dependency-free: each file is a single HTML page (fonts from
Google Fonts; no build step, no bundler, no network calls back to any service).

## `aegis-tour.html`

![Animated tour of Aegis](aegis-tour.gif)

> `aegis-tour.gif` is a recording of the page (GitHub renders HTML as source, so
> the GIF is how the animation shows up in the repo). Open the `.html` for the
> real, interactive, theme-aware page.

An animated one-page tour:

- **The operating split** — the LLM writes & plans, a typed decision model
  decides, code acts.
- **The pipeline** — an animated `recon → web → dast → triage → rank → confirm`
  flow with a sample transcript, stopping at the human confirm-to-exploit gate.
- **Two engines, one verdict** — the Strix-style dynamic graph-of-agents and the
  RAPTOR-style static hypothesis loop sharing one knowledge base + decision
  router, deduped into one ranked report.
- **Sample findings** — the real numbers from the bundled sample run (five
  accepted findings, three rejected, two engines), with an animated severity
  distribution.
- **The autonomous agent** — goal → plan phases (M24) → DAST depth (M25) →
  stage-1 confirm → chaining (M26, designed), and the "a human beat before
  payloads" gate.
- **The safety clamp** — an animated illustration of the invariant that the
  planner proposes and a pure clamp over a trusted set disposes: a hostile
  token is dropped, scope never widens.

Open it in any browser:

```bash
xdg-open demo/aegis-tour.html     # or: python3 -m http.server, then browse to it
```

The page is theme-aware (follows the viewer's light/dark setting, with a manual
toggle) and respects `prefers-reduced-motion` — every animation has a complete,
legible resting state.

> The figures shown are the committed sample run (`ui/public/data/report.json`),
> not a live scan of any real target.
