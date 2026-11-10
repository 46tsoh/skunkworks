"""Strix-style LLM deduplication, routed through the decision model.

Decide whether a candidate describes the *same underlying vulnerability* as an
already-accepted finding (same root cause, component, and fix) — one boolean
decision with confidence, instead of a full LLM completion.
"""

from __future__ import annotations

from typing import Optional, Sequence

from aegis.decision import DecisionRouter
from aegis.knowledge.models import Candidate, Finding


def _statement(cand: Candidate, exist: Candidate) -> str:
    return (
        "Two vulnerability reports describe the SAME underlying vulnerability "
        "(same root cause, same affected component, fixed by the same change). "
        "Different endpoints, parameters, or root causes are NOT duplicates.\n\n"
        f"Candidate: {cand.title} [{cand.cwe}] in {cand.component}\n"
        f"Existing:  {exist.title} [{exist.cwe}] in {exist.component}\n"
        f"[ref={cand.id}|{exist.id}]"
    )


def find_duplicate(
    router: DecisionRouter,
    cand: Candidate,
    accepted: Sequence[Finding],
) -> Optional[Candidate]:
    """Return the accepted finding this candidate duplicates, or None."""
    for finding in accepted:
        exist = finding.candidate
        if router.gate("dedupe.same_vuln", _statement(cand, exist)):
            return exist
    return None


__all__ = ["find_duplicate"]
