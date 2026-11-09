"""Self-contained CVSS v3.1 base-score calculator (Strix uses the `cvss` lib).

Implemented from the first.org CVSS v3.1 specification so the POC has no
third-party dependency. Verified against the spec's published anchors in tests.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # scope changed
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.x vector string into a metric->value dict."""
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        if key == "CVSS":  # version prefix
            continue
        metrics[key] = value.strip().upper()
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    missing = [k for k in required if k not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing metrics: {missing} in {vector!r}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: ceil to one decimal with integer-safe arithmetic."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score (0.0-10.0) for a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1.0 - (
        (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity_band(score: float) -> str:
    """Map a base score to the CVSS v3.1 qualitative severity band."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
