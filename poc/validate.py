"""RAPTOR-style staged exploitability validation, via the decision model.

Mirrors RAPTOR's ``exploitability_validation`` (``/validate``) gate chain: a
sequence of yes/no gates, each asserting one property required for the finding
to be exploitable. The first failing gate short-circuits the chain — so the
expensive later stages never run, and a model budget stretches further.

These gates reason over the *finding's text summary only*; the POC does no
exploitation and reaches no target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from reference.jev import DecisionRouter

from .models import Candidate

# (property asserted TRUE) for each stage, in order. Aligned with the generic
# chain in reference/jev/integrations/raptor_gates.py.
_STAGES: list[str] = [
    "the vulnerable code is reachable from an external entry point",
    "attacker-controlled input can reach the vulnerable location",
    "the path constraints to reach it are satisfiable",
    "the sink is genuinely dangerous in this context",
    "no effective sanitizer neutralizes the input on this path",
    "a concrete exploitation primitive is achievable",
    "the resulting impact is material (not merely theoretical)",
    "a proof-of-concept could plausibly be constructed",
]


@dataclass
class ValidationResult:
    exploitable: bool
    stages_passed: int
    failed_stage: Optional[str] = None


def validate_exploitability(router: DecisionRouter, cand: Candidate) -> ValidationResult:
    """Run the staged gate chain, short-circuiting on the first failure."""
    for i, prop in enumerate(_STAGES):
        statement = (
            f"For the candidate finding '{cand.title}' ({cand.cwe}) in "
            f"{cand.component}, {prop}. [ref={cand.id}#{i}]"
        )
        if not router.gate("validate.stage", statement):
            return ValidationResult(False, i, failed_stage=prop)
    return ValidationResult(True, len(_STAGES))
