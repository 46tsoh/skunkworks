"""Crash analysis adapter (static/deep) — classifies a crash into a vuln class.

Takes a crash/core (typically one of the fuzzing adapter's witnesses), replays
it under a debugger, and buckets it: a vulnerability class plus an
exploitability hint in the style of the GDB ``exploitable`` plugin
(``EXPLOITABLE`` / ``PROBABLY_EXPLOITABLE`` / ``PROBABLY_NOT_EXPLOITABLE`` /
``UNKNOWN``), with the faulting instruction, PC and a crash-hash for bucketing.

The adapter consumes a normalised triage-summary JSON. Live, that is produced by
a GDB + ``exploitable`` image replaying each input locally; offline, the
recorded fixture feeds the SAME :func:`parse`. No network (``--network none``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# GDB + the `exploitable` triage plugin. No single canonical public image owns
# this; AFL++ bundles comparable crash-triage tooling, so its image is the
# best-effort default. Swap for a dedicated gdb/exploitable build if preferred.
IMAGE = "aflplusplus/aflplusplus:4.21c"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "crash" / "triage.json"

# exploitable classification -> severity of the resulting candidate.
_CLASS_SEVERITY = {
    "EXPLOITABLE": "critical",
    "PROBABLY_EXPLOITABLE": "high",
    "UNKNOWN": "medium",
    "PROBABLY_NOT_EXPLOITABLE": "low",
}
# When the triage entry carries no CWE, guess from the signal.
_SIGNAL_CWE = {"SIGSEGV": "CWE-787", "SIGABRT": "CWE-787", "SIGILL": "CWE-787",
               "SIGBUS": "CWE-125", "SIGFPE": "CWE-369"}


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {}
    tgt = data.get("target") or target
    out: List[Candidate] = []
    for i, c in enumerate(data.get("crashes", []) or []):
        classification = (c.get("classification") or "UNKNOWN").upper()
        severity = _CLASS_SEVERITY.get(classification, "medium")
        signal = c.get("signal", "")
        cwe = c.get("cwe") or _SIGNAL_CWE.get(signal, "CWE-787")
        inp = c.get("input", f"crash-{i:06d}")
        exploitable = classification in {"EXPLOITABLE", "PROBABLY_EXPLOITABLE"}
        instr = c.get("faulting_instruction", "?")
        bt = c.get("backtrace", []) or []
        out.append(make_candidate(
            id=f"crash-{i+1}",
            title=f"{signal or 'Crash'} classified {classification} in {tgt}",
            cwe=cwe,
            component=f"{tgt}:{bt[0]}" if bt else tgt,
            severity=severity,
            description=(f"{c.get('description', 'Crash')} "
                         f"(pc={c.get('pc', '?')}, insn `{instr}`). "
                         f"exploitable verdict: {classification}."),
            evidence=[f"input {inp}", f"signal {signal}",
                      f"faulting instruction {instr}",
                      f"backtrace: {' -> '.join(bt)}" if bt else "no backtrace"],
            source_engine="static", tool="crash",
            rule=f"exploitable/{classification.lower()}",
            classification=classification, exploitable_hint=exploitable,
            pc=c.get("pc"), crash_hash=(c.get("hash") or {}).get("major"),
        ))
    return out


class CrashDockerTool(DockerBackedTool):
    name = "crash"
    kind = ToolKind.STATIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # Live, each crash input is replayed under gdb+exploitable and the per
        # crash verdicts are collected into the triage JSON :func:`parse` reads.
        return ["gdb", "-batch", "-ex", "run", "-ex", "exploitable",
                opts.get("binary", f"{self.container_workdir}/target"),
                self.container_workdir]


def make_docker() -> CrashDockerTool:
    return CrashDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("crash", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "CrashDockerTool", "make_docker", "make_fixture"]
