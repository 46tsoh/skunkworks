"""Web endpoint adapter (dynamic) — parses nuclei JSONL output.

nuclei exercises a running target with a library of templates and emits one JSON
object per line (``-jsonl``). Each line becomes a candidate describing the
endpoint that matched and the issue class. The same :func:`parse` feeds the
offline fixture adapter (recorded JSONL) and the Docker-backed adapter, which
runs ``nuclei`` inside a local, network-isolated container against the
authorized sample target only.

Local-only: the Docker runtime forces ``--network none``; nuclei can only reach
endpoints inside that sandbox, never the public internet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

IMAGE = "projectdiscovery/nuclei:v3.3.5"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "web" / "nuclei.jsonl"


def parse(raw: str, target: str) -> List[Candidate]:
    """Turn nuclei JSONL into candidates. Tolerant of empty/blank input."""
    out: List[Candidate] = []
    n = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip a stray non-JSON log line, keep parsing the rest
        info = r.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        template = r.get("template-id") or r.get("templateID") or f"template-{n}"
        location = r.get("matched-at") or r.get("matched") or r.get("host") or (target or "?")
        name = info.get("name", template)
        severity = info.get("severity", "info")
        cve = classification.get("cve-id") or []
        n += 1
        evidence = [f"nuclei template {template}", f"matched-at: {location}"]
        extracted = r.get("extracted-results") or []
        if extracted:
            evidence.append("extracted: " + ", ".join(str(e) for e in extracted[:3]))
        out.append(make_candidate(
            id=f"web-{n}",
            title=str(name)[:120],
            # CWE from the template's classification; fall back to the shared default.
            cwe=extract_cwe(classification.get("cwe-id")),
            component=str(location),
            severity=severity,
            description=f"nuclei template {template!r} matched at {location}.",
            evidence=evidence,
            source_engine="dynamic", tool="web",
            template=template, cve=list(cve),
        ))
    return out


class WebDockerTool(DockerBackedTool):
    name = "web"
    kind = ToolKind.DYNAMIC
    allows_network = True  # remote web scanner (nuclei)
    image = IMAGE

    def argv(self, target: str, **opts):
        # -jsonl machine-readable findings to stdout; -duc skips the remote
        # template-update check (local-only). Target URL is caller-authorized.
        url = opts.get("url", target)
        return ["nuclei", "-u", url, "-jsonl", "-silent", "-duc"]


def make_docker() -> WebDockerTool:
    return WebDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("web", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "WebDockerTool", "make_docker", "make_fixture"]
