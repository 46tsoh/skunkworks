"""POC: a Strix + RAPTOR + decision-model security-triage pipeline.

This package recreates, in original code, the *decision-shaped* patterns from
two security-analysis frameworks and routes every decision through a typed
decision model (Jev / basal-omni) via ``reference.jev``:

* **Strix-style** — a findings model, CVSS v3.1 scoring, and LLM-style
  deduplication (mirrors Strix's ``check_duplicate`` contract).
* **RAPTOR-style** — a hypothesis-driven loop with a posterior, and a staged
  exploitability-validation gate chain (mirrors RAPTOR's hypothesis_validation
  and exploitability_validation packages).

It is a *defensive engineering* demo: it operates on sample finding data, does
no scanning, no exploitation, and reaches no target. It runs fully offline and
deterministically via a stand-in backend; basal-omni/Jev drop in behind one
flag.
"""
