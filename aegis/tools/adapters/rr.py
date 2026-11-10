"""rr adapter (dynamic record-replay) — parses an rr replay summary JSON.

``rr`` (record-and-replay) records a program's execution once, then replays it
deterministically as many times as needed. Replaying under memory/thread
sanitizing passes surfaces faults that are hard to catch live — use-after-free,
double-free, uninitialized reads, and the data races whose ordering rr pins down
across replays. The Aegis replay driver writes one JSON summary per trace: the
recorded event count and a list of faults, each with its class, source location,
and the offending memory access. This adapter turns that summary into one
:class:`Candidate` per fault.

The same :func:`parse` feeds the offline fixture adapter (a recorded summary)
and the Docker-backed adapter (records+replays a local program, no network).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

# rr publishes releases on GitHub; there is no single canonical Docker Hub image,
# so this is a best-effort public reference. See 'notes' — confirm/pin the tag
# (or build from docker/README.md) before the live path is relied on. The
# fixture path used in tests needs no image.
IMAGE = "rrdebugger/rr:5.8.0"

_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "rr" / "replay-summary.json"

# Fault class (as the replay driver labels it) -> weakness class. A finding may
# override this with an explicit ``cwe`` field.
_CLASS_CWE = {
    "use-after-free": "CWE-416",
    "double-free": "CWE-415",
    "uninitialized-read": "CWE-457",
    "data-race": "CWE-362",
    "heap-overflow": "CWE-122",
    "buffer-overflow": "CWE-787",
    "null-deref": "CWE-476",
}


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"findings": []}
    out: List[Candidate] = []
    for i, f in enumerate(data.get("findings", []) or []):
        fault = f.get("class", "anomaly")
        cwe = extract_cwe(f.get("cwe"), default=_CLASS_CWE.get(fault, "CWE-693"))
        location = f.get("location", "?")
        access = f.get("access", "")
        event = f.get("event")
        evidence = [f"rr replay observed {fault} at {location}"]
        if access:
            evidence.append(f"access: {access}")
        if f.get("freed_at"):
            evidence.append(f"memory freed at: {f['freed_at']}")
        if f.get("allocated_at"):
            evidence.append(f"allocated at: {f['allocated_at']}")
        if event is not None:
            evidence.append(f"deterministic replay event #{event}")
        out.append(make_candidate(
            id=f"rr-{i+1}",
            title=f"{fault} observed during deterministic replay",
            cwe=cwe,
            component=location,
            severity=f.get("severity", "medium"),
            description=(f"rr replayed the recorded trace and observed a "
                         f"{fault} at {location}."),
            evidence=evidence,
            source_engine="dynamic", tool="rr",
            fault_class=fault, replay_event=event,
            deterministic=f.get("deterministic"),
        ))
    return out


class RrDockerTool(DockerBackedTool):
    name = "rr"
    kind = ToolKind.DYNAMIC
    image = IMAGE
    timeout_s = 300.0  # record + several replay passes

    def argv(self, target: str, **opts):
        # Record the target once, then run the Aegis replay-analysis pass, which
        # prints the replay-summary JSON to stdout. `target` is the program path
        # (mounted read-only at the container workdir). rr needs a performance
        # counter; on hosts without one the run degrades to ERROR, not a crash.
        return ["aegis-rr-replay", "--json", target]


def make_docker() -> RrDockerTool:
    return RrDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("rr", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "RrDockerTool", "make_docker", "make_fixture"]
