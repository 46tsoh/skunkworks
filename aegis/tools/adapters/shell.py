"""Shell / command-exec adapter (dynamic) — parses a scripted scanner's stdout.

A small scripted scanner CLI is run against the authorized target inside a
**local, no-network** container; it prints one line per issue it spots. The same
:func:`parse` feeds both the fixture adapter (offline, recorded stdout) and the
Docker-backed adapter, so the line parser (the bug-prone part) is pinned without
any binary or network.

Recorded stdout lines look like::

    [HIGH]   CWE-78  scripts/deploy.sh:47  OS command injection: ...
    [MEDIUM] CWE-22  scripts/backup.sh:12  Path traversal: ...

i.e. ``[SEVERITY] CWE-<n> <component> <message>``. Everything else (banners,
rules, counts) is ignored, so the parser tolerates arbitrary surrounding noise
and empty input.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

# alpine is a minimal, public base; the scripted scanner is invoked via `sh -c`.
# NOTE: alpine itself ships no scanner — in a real deployment the scan command
# (or an image with the scanner baked in) is supplied via opts["command"]; the
# tag here is a safe placeholder, see module notes.
IMAGE = "alpine:3.20"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "shell" / "scan.txt"

# Default scripted scan: a conservative, dependency-free sweep of the mounted
# read-only target. Overridable via opts["command"].
_DEFAULT_SCAN = (
    "echo 'sca-shell-scan (scripted)'; "
    "grep -rnE 'eval |system\\(|os\\.system|subprocess|\\$\\(' /work 2>/dev/null | head -n 50 || true"
)

_LINE_RE = re.compile(
    r"^\[(?P<sev>[A-Za-z]+)\]\s+(?P<cwe>CWE-\d+)\s+(?P<component>\S+)\s+(?P<msg>.+?)\s*$"
)


def parse(raw: str, target: str) -> List[Candidate]:
    out: List[Candidate] = []
    i = 0
    for line in (raw or "").splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        i += 1
        msg = m.group("msg").strip()
        out.append(make_candidate(
            id=f"shell-{i}",
            title=msg[:120],
            cwe=extract_cwe(m.group("cwe")),
            component=m.group("component"),
            severity=m.group("sev"),
            description=msg,
            evidence=[f"scanner line: {line.strip()}", m.group("component")],
            source_engine="dynamic", tool="shell",
        ))
    return out


class ShellDockerTool(DockerBackedTool):
    name = "shell"
    kind = ToolKind.DYNAMIC
    image = IMAGE

    def argv(self, target: str, **opts):
        return ["sh", "-c", opts.get("command", _DEFAULT_SCAN)]


def make_docker() -> ShellDockerTool:
    return ShellDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("shell", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ShellDockerTool", "make_docker", "make_fixture"]
