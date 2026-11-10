"""Illustrative Strix integration: agent-graph routing + findings triage.

Strix (``github.com/usestrix/strix``) is a "Graph of Agents" that spends LLM
tokens on two high-frequency decision types we can offload:

1. **Routing** — which specialist agent / tool to invoke next (a choose-one
   over an enumerable set).
2. **Findings triage** — is a candidate finding a true positive worth an
   (expensive) LLM write-up, and how severe is it?

The cleanest delivery path that avoids forking Strix core is to expose these as
a **Strix Skill** (``SKILL.md``) or an **MCP server** tool; this module is the
decision core such a skill/server would call.

Nothing here imports Strix — it only depends on the local decision layer, so it
is importable and testable on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..router import DecisionRouter

# Suggested threshold set. Triage is deliberately low so the gate errs toward
# *keeping* findings (a dropped real vuln is worse than a wasted write-up).
STRIX_THRESHOLDS = {
    "strix.triage_true_positive": 0.35,
    "strix.should_escalate": 0.6,
}


@dataclass
class Finding:
    title: str
    evidence: str
    endpoint: str = ""


class StrixDecisions:
    """Decision helpers for a Strix orchestrator or skill."""

    def __init__(self, router: DecisionRouter) -> None:
        self.router = router

    def route_next_agent(
        self, context: str, available_agents: Sequence[str]
    ) -> str:
        """Pick which specialist agent to run next (choose-one).

        Use for the *enumerable* routing decisions; leave genuinely open-ended
        "what should we even try" reasoning on the main LLM.
        """
        result = self.router.choose(
            "strix.route_next_agent",
            prompt=(
                "Given the current test state, which specialist agent should "
                f"act next to make progress?\n\nState:\n{context}"
            ),
            options=list(available_agents),
        )
        return result.option

    def is_true_positive(self, finding: Finding) -> bool:
        """Triage gate run *before* any LLM write-up/PoC is generated."""
        return self.router.gate(
            "strix.triage_true_positive",
            statement=(
                f"The following is a genuine, exploitable security finding "
                f"(not a false positive):\n"
                f"Title: {finding.title}\n"
                f"Endpoint: {finding.endpoint}\n"
                f"Evidence: {finding.evidence}"
            ),
        )

    def severity_score(self, finding: Finding) -> float:
        """0-10 severity band (CVSS-like) to prioritize reporting order."""
        return self.router.score(
            "strix.severity",
            prompt=(
                "Rate the security severity of this finding.\n"
                f"Title: {finding.title}\nEvidence: {finding.evidence}"
            ),
            scale_min=0.0,
            scale_max=10.0,
        ).value

    def triage(self, findings: Sequence[Finding]) -> list[Finding]:
        """Drop likely false positives, return survivors sorted by severity.

        This is the token-saving hot path: only survivors get an LLM write-up.
        """
        kept = [f for f in findings if self.is_true_positive(f)]
        return sorted(kept, key=self.severity_score, reverse=True)
