"""Illustrative RAPTOR integration: the /validate exploitability gate chain.

RAPTOR (``github.com/gadievron/raptor``) runs an **eight-stage exploitability
check** (``/validate``) and a hypothesis-driven audit engine. Each validation
stage is a yes/no gate with evidence — a perfect fit for a calibrated boolean
decision. Modeling the chain this way means:

* an early gate failing **short-circuits** the chain without spending LLM
  budget on later stages (``--max-cost-usd`` goes further);
* each stage has its *own* threshold, so you tune false-positive vs
  false-negative per stage;
* the whole chain is deterministic given a backend, so it is unit-testable.

Recommended wiring: place the decision client **behind RAPTOR's existing LLM
dispatcher** so worker processes call it over the current socket and never hold
API keys. In ``--no-llm`` mode, back it with ``StaticBackend`` to keep that mode
genuinely model-free.

The stage list below mirrors the *shape* of an eight-stage check; map the
statements to RAPTOR's real stage definitions when integrating.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..router import DecisionRouter

# Conservative per-stage thresholds: a stage only *blocks* when the model is
# fairly confident the property fails, biasing toward continued investigation.
RAPTOR_VALIDATE_THRESHOLDS = {
    "raptor.validate.reachable": 0.5,
    "raptor.validate.input_controlled": 0.5,
    "raptor.validate.constraints_satisfiable": 0.45,
    "raptor.validate.sink_dangerous": 0.5,
    "raptor.validate.sanitizer_absent": 0.5,
    "raptor.validate.primitive_achievable": 0.5,
    "raptor.validate.impact_material": 0.5,
    "raptor.validate.poc_plausible": 0.4,
}

# (stage_kind, human-readable property the gate asserts is TRUE)
_STAGES: list[tuple[str, str]] = [
    ("raptor.validate.reachable",
     "the vulnerable code is reachable from an external entry point"),
    ("raptor.validate.input_controlled",
     "attacker-controlled input can reach the vulnerable location"),
    ("raptor.validate.constraints_satisfiable",
     "the path constraints to reach it are satisfiable"),
    ("raptor.validate.sink_dangerous",
     "the sink is genuinely dangerous in this context"),
    ("raptor.validate.sanitizer_absent",
     "no effective sanitizer/validation neutralizes the input on this path"),
    ("raptor.validate.primitive_achievable",
     "a concrete exploitation primitive is achievable"),
    ("raptor.validate.impact_material",
     "the resulting impact is material (not merely theoretical)"),
    ("raptor.validate.poc_plausible",
     "a proof-of-concept could plausibly be constructed"),
]


@dataclass
class ValidationResult:
    exploitable: bool
    stages_passed: int
    failed_stage: Optional[str] = None
    trace: list[tuple[str, bool]] = field(default_factory=list)


class RaptorValidateChain:
    """Eight-stage exploitability gate chain backed by typed decisions."""

    def __init__(self, router: DecisionRouter) -> None:
        self.router = router

    def validate(self, finding_summary: str) -> ValidationResult:
        """Run the chain, short-circuiting on the first failing gate.

        ``finding_summary`` is RAPTOR's text summary of the candidate (binary
        artifacts etc. must be summarized to text upstream, as RAPTOR already
        does for its LLM calls).
        """
        trace: list[tuple[str, bool]] = []
        for i, (kind, prop) in enumerate(_STAGES):
            passed = self.router.gate(
                kind,
                statement=(
                    f"For the following candidate finding, {prop}.\n\n"
                    f"Finding:\n{finding_summary}"
                ),
            )
            trace.append((kind, passed))
            if not passed:
                return ValidationResult(
                    exploitable=False,
                    stages_passed=i,
                    failed_stage=kind,
                    trace=trace,
                )
        return ValidationResult(
            exploitable=True, stages_passed=len(_STAGES), trace=trace
        )

    def hypothesis_priority(self, hypothesis: str) -> float:
        """Score (0-10) how worth-pursuing an audit hypothesis is."""
        return self.router.score(
            "raptor.hypothesis_priority",
            prompt=(
                "Rate how worthwhile it is to investigate this security "
                f"hypothesis next:\n{hypothesis}"
            ),
            scale_min=0.0,
            scale_max=10.0,
        ).value
