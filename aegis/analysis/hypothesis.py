"""RAPTOR-style hypothesis posterior, routed through the decision model.

Treats each candidate as a hypothesis ("this is a genuine, evidence-supported
vulnerability"), gathers its evidence, and estimates a posterior probability
via the decision model's ``score`` mode over a 0..1 scale.
"""

from __future__ import annotations

from aegis.decision import DecisionRouter
from aegis.knowledge.models import Candidate


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


__all__ = ["posterior"]
