"""Fuzzing adapter (static/deep) — surfaces crashing inputs from an AFL++ run.

A time-boxed, local AFL++ campaign against a harness leaves two things behind: a
``fuzzer_stats`` key/value file describing the run, and a ``crashes/`` directory
of inputs that triggered a fault, each named with the AFL metadata string
(``id:…,sig:11,src:…,op:havoc,…``). Every saved crash is one candidate — a
memory-corruption witness in the CWE-787 (out-of-bounds write) / CWE-125
(out-of-bounds read) class, bucketed by the terminating signal.

The adapter consumes a normalised JSON collection of ``fuzzer_stats`` plus the
crash listing. Live, that is collected from the AFL++ output directory inside a
local ``aflplusplus`` image; offline, the recorded fixture feeds the SAME
:func:`parse`. Nothing reaches the network (``--network none``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

IMAGE = "aflplusplus/aflplusplus:4.21c"  # best-effort tag; bump to a local build
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "fuzz" / "campaign.json"

# Terminating signal -> likely memory-safety class. SEGV on a write and ABRT
# (stack/heap guard trip) read as out-of-bounds writes; a bare SEGV read is the
# out-of-bounds-read case. Default to the write class (more severe).
_SIGNAL_CWE = {
    "4": "CWE-787",   # SIGILL  (corrupted control flow)
    "6": "CWE-787",   # SIGABRT (guard / heap corruption)
    "8": "CWE-125",   # SIGFPE
    "11": "CWE-787",  # SIGSEGV
}
_SIGNAL_NAME = {"4": "SIGILL", "6": "SIGABRT", "8": "SIGFPE", "11": "SIGSEGV"}
_KV_RE = re.compile(r"([A-Za-z0-9_]+)\s*:\s*([^,]+)")


def _crash_fields(name: str) -> dict:
    """Pull the ``key:value`` pairs out of an AFL crash filename."""
    return {k: v.strip() for k, v in _KV_RE.findall(name)}


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {}
    stats = data.get("fuzzer_stats", {}) or {}
    comp = data.get("target") or stats.get("afl_banner") or target
    out: List[Candidate] = []
    for i, name in enumerate(data.get("crashes", []) or []):
        fields = _crash_fields(name)
        sig = str(fields.get("sig", "")).lstrip("0") or fields.get("sig", "")
        cwe = _SIGNAL_CWE.get(sig, "CWE-787")
        signame = _SIGNAL_NAME.get(sig, f"signal {fields.get('sig', '?')}")
        cid = fields.get("id", f"{i:06d}")
        out.append(make_candidate(
            id=f"fuzz-{i+1}",
            title=f"Fuzzing crash ({signame}) in {comp}",
            cwe=cwe,
            component=f"{comp}:crash-{cid}",
            severity="high",
            description=(f"A saved AFL++ input faults {comp} with {signame} "
                         f"after {fields.get('execs', '?')} executions; a "
                         "reproducible memory-safety crash."),
            evidence=[f"crash input {name}",
                      f"stats: {stats.get('saved_crashes', '?')} crashes / "
                      f"{stats.get('execs_done', '?')} execs"],
            source_engine="static", tool="fuzz",
            rule=f"afl/{signame.lower()}", signal=signame,
            crash_input=name, afl_op=fields.get("op"),
        ))
    return out


class FuzzDockerTool(DockerBackedTool):
    name = "fuzz"
    kind = ToolKind.STATIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # Live, a time-boxed campaign runs then the output dir is collected to
        # the JSON :func:`parse` reads. Shown here is the campaign invocation;
        # `opts` can override timeout/harness. Degrades to the fixture offline.
        secs = str(opts.get("fuzz_seconds", 3600))
        harness = opts.get("harness", "./harness")
        return ["afl-fuzz", "-i", f"{self.container_workdir}/seeds",
                "-o", f"{self.container_workdir}/out", "-V", secs,
                "--", harness]


def make_docker() -> FuzzDockerTool:
    return FuzzDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("fuzz", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "FuzzDockerTool", "make_docker", "make_fixture"]
