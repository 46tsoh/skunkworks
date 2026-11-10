"""The combined analysis pipeline: Strix + RAPTOR patterns, decision-driven.

Per candidate finding, in order:

1. **Triage** (Strix)      — true-positive gate; drop likely false positives
   before any further (expensive) work.
2. **Hypothesis** (RAPTOR) — estimate a posterior from evidence; drop
   unsupported hypotheses.
3. **Dedupe** (Strix)      — collapse into an already-accepted finding if it is
   the same underlying vulnerability.
4. **Validate** (RAPTOR)   — staged exploitability gate chain (short-circuits).
5. **Score** (Strix)       — CVSS v3.1 base score + severity band.

Accepted findings land in a shared :class:`~aegis.knowledge.base.KnowledgeBase`
and are ranked exploitable-first, then CVSS, then posterior. Every decision in
steps 1-4 goes through the :class:`DecisionRouter`, so the whole run is logged,
cached, threshold-tuned, and (with the stand-in backend) reproducible.
"""

from __future__ import annotations

from typing import Sequence

from aegis.analysis import cvss
from aegis.analysis.dedupe import find_duplicate
from aegis.analysis.hypothesis import posterior as hypothesis_posterior
from aegis.analysis.triage import is_true_positive
from aegis.analysis.validate import validate_exploitability
from aegis.config import DEFAULT_POSTERIOR_MIN
from aegis.decision import DecisionRouter
from aegis.knowledge.base import KnowledgeBase
from aegis.knowledge.models import Candidate, Finding


def run(
    router: DecisionRouter,
    candidates: Sequence[Candidate],
    posterior_min: float = DEFAULT_POSTERIOR_MIN,
    kb: KnowledgeBase = None,
) -> KnowledgeBase:
    """Run the pipeline over ``candidates`` into a knowledge base.

    If ``kb`` is given, findings are added to it (letting a second engine fold
    its results into a shared base); otherwise a fresh one is returned.
    """
    if kb is None:
        kb = KnowledgeBase()
    stage_counts = {
        "triage": 0, "hypothesis": 0, "dedupe": 0,
        "validated_exploitable": 0, "validated_informational": 0,
    }

    for cand in candidates:
        # 1. Triage (Strix): cheap gate before anything expensive.
        if not is_true_positive(router, cand):
            kb.add_rejection(cand, "triage", "likely false positive")
            stage_counts["triage"] += 1
            continue

        # 2. Hypothesis posterior (RAPTOR).
        post = hypothesis_posterior(router, cand)
        if post < posterior_min:
            kb.add_rejection(
                cand, "hypothesis", f"posterior {post:.2f} < {posterior_min}"
            )
            stage_counts["hypothesis"] += 1
            continue

        # 3. Dedupe (Strix) against already-accepted findings.
        dup = find_duplicate(router, cand, kb.accepted)
        if dup is not None:
            kb.add_rejection(
                cand, "dedupe", f"duplicate of {dup.id} ({dup.title})"
            )
            stage_counts["dedupe"] += 1
            continue

        # 4. Exploitability validation (RAPTOR).
        val = validate_exploitability(router, cand)
        if val.exploitable:
            stage_counts["validated_exploitable"] += 1
        else:
            stage_counts["validated_informational"] += 1

        # 5. CVSS scoring (Strix).
        score = cvss.base_score(cand.cvss_vector)
        kb.add_finding(
            Finding(
                candidate=cand,
                posterior=post,
                cvss_score=score,
                severity=cvss.severity_band(score),
                exploitable=val.exploitable,
                stages_passed=val.stages_passed,
                failed_stage=val.failed_stage,
            )
        )

    kb.rank()
    kb.metrics = {
        "candidates": len(candidates),
        "accepted": len(kb.accepted),
        "rejected": len(kb.rejected),
        "stage_counts": stage_counts,
        "decisions": router.metrics.calls,
        "decision_cache_hits": router.metrics.cache_hits,
        "decisions_by_backend": dict(router.metrics.by_backend),
    }
    return kb


__all__ = ["run"]
