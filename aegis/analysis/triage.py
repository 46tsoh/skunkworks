"""Strix-style true-positive triage gate, routed through the decision model.

A cheap boolean gate run *before* any expensive downstream work, so likely
false positives are dropped first. Reasons over the candidate's text summary
only; it reaches no target.
"""

from __future__ import annotations

from aegis.decision import DecisionRouter
from aegis.knowledge.models import Candidate


def triage_statement(cand: Candidate) -> str:
    return (
        f"The report '{cand.title}' ({cand.cwe}) in {cand.component} is a "
        "genuine, exploitable security finding and not a false positive.\n"
        f"Details: {cand.description}\n"
        f"[ref={cand.id}]"
    )


def is_true_positive(router: DecisionRouter, cand: Candidate) -> bool:
    """Return True if the candidate survives the true-positive gate."""
    return router.gate("triage.true_positive", triage_statement(cand))


__all__ = ["triage_statement", "is_true_positive"]
