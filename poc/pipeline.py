"""The combined triage pipeline: Strix + RAPTOR patterns, decision-model driven.

Per candidate finding, in order:

1. **Triage** (Strix)      — true-positive gate; drop likely false positives
   *before* any further (expensive) work.
2. **Hypothesis** (RAPTOR) — estimate a posterior from evidence; drop
   unsupported hypotheses.
3. **Dedupe** (Strix)      — collapse into an already-accepted finding if it is
   the same underlying vulnerability.
4. **Validate** (RAPTOR)   — staged exploitability gate chain (short-circuits).
5. **Score** (Strix)       — CVSS v3.1 base score + severity band.

Accepted findings are ranked: exploitable first, then CVSS, then posterior.
Every decision in steps 1-4 goes through the DecisionRouter, so the whole run
is logged, cached, threshold-tuned, and (with the stand-in backend) reproducible.
"""

from __future__ import annotations

from typing import Optional, Sequence

from reference.jev import DecisionRouter

from . import cvss
from .backends import POSTERIOR_MIN
from .dedupe import find_duplicate
from .hypothesis import posterior as hypothesis_posterior
from .models import Candidate, PipelineResult, Rejection, ReportFinding
from .validate import validate_exploitability


def _triage_statement(cand: Candidate) -> str:
    return (
        f"The report '{cand.title}' ({cand.cwe}) in {cand.component} is a "
        "genuine, exploitable security finding and not a false positive.\n"
        f"Details: {cand.description}\n"
        f"[ref={cand.id}]"
    )


def run(router: DecisionRouter, candidates: Sequence[Candidate]) -> PipelineResult:
    result = PipelineResult()
    stage_counts: dict[str, int] = {
        "triage": 0, "hypothesis": 0, "dedupe": 0,
        "validated_exploitable": 0, "validated_informational": 0,
    }

    for cand in candidates:
        # 1. Triage (Strix): cheap gate before anything expensive.
        if not router.gate("triage.true_positive", _triage_statement(cand)):
            result.rejected.append(
                Rejection(cand, "triage", "likely false positive")
            )
            stage_counts["triage"] += 1
            continue

        # 2. Hypothesis posterior (RAPTOR).
        post = hypothesis_posterior(router, cand)
        if post < POSTERIOR_MIN:
            result.rejected.append(
                Rejection(cand, "hypothesis",
                          f"posterior {post:.2f} < {POSTERIOR_MIN}")
            )
            stage_counts["hypothesis"] += 1
            continue

        # 3. Dedupe (Strix) against already-accepted findings.
        dup = find_duplicate(router, cand, result.accepted)
        if dup is not None:
            result.rejected.append(
                Rejection(cand, "dedupe", f"duplicate of {dup.id} ({dup.title})")
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
        result.accepted.append(
            ReportFinding(
                candidate=cand,
                posterior=post,
                cvss_score=score,
                severity=cvss.severity_band(score),
                exploitable=val.exploitable,
                stages_passed=val.stages_passed,
                failed_stage=val.failed_stage,
            )
        )

    # Rank: exploitable first, then CVSS, then posterior.
    result.accepted.sort(
        key=lambda f: (f.exploitable, f.cvss_score, f.posterior), reverse=True
    )

    result.metrics = {
        "candidates": len(candidates),
        "accepted": len(result.accepted),
        "rejected": len(result.rejected),
        "stage_counts": stage_counts,
        "decisions": router.metrics.calls,
        "decision_cache_hits": router.metrics.cache_hits,
        "decisions_by_backend": dict(router.metrics.by_backend),
    }
    return result
