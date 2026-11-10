# Bundled sample target

A synthetic, **authorized** local target for exercising Aegis end-to-end. It is
not a real application and reaches no third-party host — it is a pair of
candidate sets representing what each engine would surface on the same toy app:

- `candidates_dynamic.json` — what the **DynamicEngine** (black-box) finds by
  exercising the running app (SQLi, reflected XSS, SSRF, plus one informational
  false positive).
- `candidates_static.json` — what the **StaticEngine** (source audit) finds
  (the same SQLi seen in source, a documented-test-key false positive, a
  non-exploitable buffer over-read, weak password hashing).

`S1` carries `hints.duplicate_of = "D1"`: both engines independently surface the
login SQL injection, so the orchestrator's **cross-engine dedup** collapses the
static finding into the stronger dynamic one — the unified report shows it once.

Each candidate carries `hints` (sample ground truth) so the offline `static`
decision backend makes a run fully deterministic; real backends ignore `hints`.
