"""Semgrep adapter (static SAST) — parses `semgrep --json` output.

The same :func:`parse` feeds both the fixture adapter (offline, recorded output)
and the Docker-backed adapter (runs `semgrep/semgrep` locally, no network).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, Parser, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

IMAGE = "semgrep/semgrep:1.95.0"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "semgrep" / "results.json"


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"results": []}
    out: List[Candidate] = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        path = r.get("path", "?")
        line = (r.get("start", {}) or {}).get("line", 0)
        check = r.get("check_id", f"rule-{i}")
        out.append(make_candidate(
            id=f"semgrep-{i+1}",
            title=extra.get("message", check).strip().split("\n")[0][:120],
            cwe=extract_cwe(meta.get("cwe")),
            component=f"{path}:{line}",
            severity=extra.get("severity", "warning"),
            description=extra.get("message", ""),
            evidence=[f"semgrep rule {check}", f"{path}:{line}"],
            source_engine="static", tool="semgrep",
            rule=check, owasp_meta=meta.get("owasp"),
        ))
    return out


class SemgrepDockerTool(DockerBackedTool):
    name = "semgrep"
    kind = ToolKind.STATIC
    image = IMAGE

    def argv(self, target: str, **opts):
        return ["semgrep", "--config", opts.get("config", "auto"),
                "--json", "--quiet", self.container_workdir]


def make_docker() -> SemgrepDockerTool:
    return SemgrepDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("semgrep", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "SemgrepDockerTool", "make_docker", "make_fixture"]
