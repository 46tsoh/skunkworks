"""Python sandbox adapter (dynamic) — confirms candidates in a capped container.

A short validation script runs inside a **resource-capped, no-network**
``python:3.12-slim`` container (the caps and ``--network none`` are enforced by
:func:`aegis.tools.runtime.run_container`). The script attempts to actually
trigger each suspected issue and prints a JSON verdict; only the entries it
*confirmed* become candidates. The same :func:`parse` feeds the fixture adapter
(offline, recorded JSON) and the live Docker-backed adapter.

Result JSON shape::

    {"confirmed": [{"id","cwe","component","title","severity","detail",
                    "reproduced"}, ...],
     "unconfirmed": [...]}

Only ``confirmed`` yields candidates; ``unconfirmed`` is informational.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

IMAGE = "python:3.12-slim"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "sandbox" / "result.json"

# Default validation driver. A real run supplies the per-candidate validation
# body via opts["script"]; this template emits a well-formed empty verdict so a
# live run with no driver degrades to "nothing confirmed" rather than crashing.
# NOTE: this is a template, not a full exploit harness — see module notes.
_DEFAULT_VALIDATOR = (
    "import json; print(json.dumps({'tool': 'sandbox', 'confirmed': [], "
    "'unconfirmed': []}))"
)


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if (raw or "").strip() else {}
    out: List[Candidate] = []
    for i, item in enumerate(data.get("confirmed", []) or []):
        detail = item.get("detail", "")
        out.append(make_candidate(
            id=item.get("id", f"sandbox-{i+1}"),
            title=(item.get("title") or "sandbox-confirmed issue")[:120],
            cwe=extract_cwe(item.get("cwe")),
            component=item.get("component", "?"),
            severity=item.get("severity", "medium"),
            description=detail,
            evidence=["validated in resource-capped, no-network sandbox", detail],
            source_engine="dynamic", tool="sandbox",
            reproduced=bool(item.get("reproduced", False)),
        ))
    return out


class SandboxDockerTool(DockerBackedTool):
    name = "sandbox"
    kind = ToolKind.DYNAMIC
    image = IMAGE
    timeout_s = 60.0

    def argv(self, target: str, **opts):
        return ["python", "-I", "-c", opts.get("script", _DEFAULT_VALIDATOR)]


def make_docker() -> SandboxDockerTool:
    return SandboxDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("sandbox", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "SandboxDockerTool", "make_docker", "make_fixture"]
