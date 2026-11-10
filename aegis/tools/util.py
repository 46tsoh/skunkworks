"""Shared helpers for tool adapters: CWE extraction, CVSS defaults, candidates.

Tools emit findings in wildly different shapes; these helpers normalise them
into :class:`Candidate` objects consistently. A tool that does not emit a CVSS
vector gets a conservative default derived from its severity, so every candidate
can be scored by the pipeline.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Union

from aegis.knowledge.models import Candidate

# Conservative default CVSS v3.1 vectors by qualitative severity. Used only when
# a tool does not provide its own vector.
_SEVERITY_VECTORS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low": "AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "info": "AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
}
_SEVERITY_ALIASES = {
    "error": "high", "warning": "medium", "warn": "medium", "note": "low",
    "information": "info", "informational": "info", "none": "info",
    "moderate": "medium", "important": "high",
}
_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


def normalize_severity(severity: str) -> str:
    s = (severity or "").strip().lower()
    return _SEVERITY_ALIASES.get(s, s if s in _SEVERITY_VECTORS else "medium")


def default_cvss_vector(severity: str) -> str:
    return _SEVERITY_VECTORS[normalize_severity(severity)]


def extract_cwe(value: Union[str, Iterable, None], default: str = "CWE-693") -> str:
    """Pull a canonical ``CWE-<n>`` from a string or list of strings.

    Default ``CWE-693`` (Protection Mechanism Failure) when none is present.
    """
    if value is None:
        return default
    if isinstance(value, str):
        m = _CWE_RE.search(value)
        return f"CWE-{m.group(1)}" if m else default
    for item in value:
        m = _CWE_RE.search(str(item))
        if m:
            return f"CWE-{m.group(1)}"
    return default


def make_candidate(
    *,
    id: str,
    title: str,
    cwe: str,
    component: str,
    severity: str = "medium",
    description: str = "",
    evidence: Optional[list] = None,
    cvss_vector: Optional[str] = None,
    source_engine: str = "unknown",
    hints: Optional[dict] = None,
    tool: Optional[str] = None,
    **metadata,
) -> Candidate:
    """Build a normalised :class:`Candidate` from a tool's finding."""
    md = dict(metadata)
    if tool:
        md["tool"] = tool
    return Candidate(
        id=id, title=title, cwe=cwe, component=component,
        cvss_vector=cvss_vector or default_cvss_vector(severity),
        description=description, evidence=list(evidence or []),
        hints=dict(hints or {}), source_engine=source_engine, metadata=md,
    )


__all__ = [
    "normalize_severity", "default_cvss_vector", "extract_cwe", "make_candidate",
]
