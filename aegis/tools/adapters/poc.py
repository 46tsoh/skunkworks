"""PoC-generation adapter (dynamic, host-local) — annotates with a proof.

Unlike the other dynamic adapters this one runs **on the host** via
:func:`aegis.tools.runtime.run_local` (gated on ``shutil.which("python3")``): it
drives a small PoC generator that tries to turn a suspected issue into a
runnable, reproduced proof-of-concept, then emits a JSON result. Each generated
PoC becomes a candidate that *carries the proof* in its ``evidence`` and
``metadata`` — it **proves**, it does not score (no severity/posterior decision
is made here; that is the pipeline's job).

The same :func:`parse` feeds the fixture adapter (offline, recorded JSON) and
the host adapter. Result JSON shape::

    {"generated": [{"id","cwe","component","title","severity","reproduced",
                    "script","proof","observed"}, ...]}
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools import runtime
from aegis.tools.base import FixtureTool, Parser, ToolKind, ToolResult, ToolStatus
from aegis.tools.util import extract_cwe, make_candidate

# Host-local tool: no container image. A real driver is supplied via
# opts["script"]; the template below emits an empty (nothing-proved) result so a
# live run without a driver degrades cleanly. NOTE: template, not a full
# exploit generator — see module notes.
IMAGE = ""
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "poc" / "poc.json"

_DEFAULT_DRIVER = (
    "import json; print(json.dumps({'tool': 'poc', 'generated': []}))"
)


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if (raw or "").strip() else {}
    out: List[Candidate] = []
    for i, item in enumerate(data.get("generated", []) or []):
        proof = item.get("proof", "")
        observed = item.get("observed", "")
        out.append(make_candidate(
            id=item.get("id", f"poc-{i+1}"),
            title=(item.get("title") or "proof-of-concept")[:120],
            cwe=extract_cwe(item.get("cwe")),
            component=item.get("component", "?"),
            severity=item.get("severity", "medium"),
            description=observed,
            evidence=[f"PoC proof: {proof}", f"observed: {observed}"],
            source_engine="dynamic", tool="poc",
            poc_proof=proof, poc_script=item.get("script", ""),
            poc_observed=observed, reproduced=bool(item.get("reproduced", False)),
        ))
    return out


class PocHostTool:
    """Host-local tool: runs a PoC generator with :func:`runtime.run_local`.

    Mirrors :class:`~aegis.tools.base.DockerBackedTool`'s degradation contract:
    a missing ``python3`` -> ``UNAVAILABLE``; any exception -> ``ERROR``; never
    raises.
    """

    name = "poc"
    kind = ToolKind.DYNAMIC
    requires_binary = "python3"
    timeout_s = 60.0

    def __init__(self, parser: Parser) -> None:
        self._parser = parser

    def available(self) -> bool:
        return shutil.which(self.requires_binary) is not None

    def argv(self, target: str, **opts):
        return [self.requires_binary, "-I", "-c", opts.get("script", _DEFAULT_DRIVER)]

    def run(self, target: str, **opts) -> ToolResult:
        t0 = time.perf_counter()
        if not self.available():
            return ToolResult(
                self.name, ToolStatus.UNAVAILABLE, target=target,
                errors=[f"{self.requires_binary!r} not found on host; install it "
                        "or use the fixture adapter"])
        try:
            cr = runtime.run_local(self.argv(target, **opts), timeout_s=self.timeout_s)
            raw = cr.stdout + (("\n[stderr]\n" + cr.stderr) if cr.stderr else "")
            cands = self._parser(cr.stdout, target)
            for c in cands:
                c.metadata.setdefault("tool", self.name)
            status = ToolStatus.OK if not cr.timed_out else ToolStatus.ERROR
            errors = ["timed out"] if cr.timed_out else []
            return ToolResult(
                self.name, status, candidates=cands, raw=raw, target=target,
                errors=errors,
                metadata={"binary": self.requires_binary, "exit": cr.exit_code},
                duration_ms=(time.perf_counter() - t0) * 1000.0)
        except Exception as exc:
            return ToolResult(
                self.name, ToolStatus.ERROR, target=target,
                errors=[f"{type(exc).__name__}: {exc}"],
                duration_ms=(time.perf_counter() - t0) * 1000.0)


def make_host() -> PocHostTool:
    return PocHostTool(parser=parse)


# Alias so the registry's generic ``make_docker()`` probe still finds a live
# adapter for this (host-local) capability.
make_docker = make_host


def make_fixture() -> FixtureTool:
    return FixtureTool("poc", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="python3")


__all__ = ["IMAGE", "parse", "PocHostTool", "make_host", "make_docker",
           "make_fixture"]
