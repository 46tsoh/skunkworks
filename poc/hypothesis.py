"""RAPTOR-style hypothesis posterior, routed through the decision model.

Mirrors the shape of RAPTOR's ``hypothesis_validation`` package: treat each
candidate as a hypothesis ("this is a genuine, evidence-supported
vulnerability"), gather its evidence, and estimate a posterior probability. The
decision model's ``score`` mode (0..1) stands in for the posterior estimate.
"""

from __future__ import annotations

from reference.jev import DecisionRouter

from .models import Candidate


def posterior(router: DecisionRouter, cand: Candidate) -> float:
    """Estimate P(hypothesis true | evidence) in [0, 1]."""
    evidence = "; ".join(cand.evidence) if cand.evidence else "(none provided)"
    statement = (
        f"Hypothesis: '{cand.title}' ({cand.cwe}) in {cand.component} is a "
        "genuine, evidence-supported vulnerability.\n"
        f"Evidence gathered: {evidence}\n"
        f"[ref={cand.id}]"
    )
    return router.score("hypothesis.posterior", statement, 0.0, 1.0).value
