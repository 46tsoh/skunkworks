"""Load candidate findings from a JSON array file into Candidate objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from aegis.knowledge.models import Candidate

_CANDIDATE_FIELDS = {
    "id", "title", "cwe", "component", "cvss_vector",
    "description", "evidence", "hints", "source_engine", "metadata",
}


def load_candidates(path, source_engine: Optional[str] = None) -> list:
    """Parse a JSON array of candidate dicts; unknown keys go to ``metadata``.

    If ``source_engine`` is given, it is stamped on every candidate (unless the
    item already declares one).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for item in data:
        known = {k: v for k, v in item.items() if k in _CANDIDATE_FIELDS}
        extra = {k: v for k, v in item.items() if k not in _CANDIDATE_FIELDS}
        if extra:
            known.setdefault("metadata", {}).update(extra)
        if source_engine and "source_engine" not in known:
            known["source_engine"] = source_engine
        out.append(Candidate(**known))
    return out


__all__ = ["load_candidates"]
