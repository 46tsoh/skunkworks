"""Binary analysis adapter (static/deep) — inspects a compiled artifact.

Looks at a binary for two classes of weakness: missing exploit-mitigation
("hardening") flags such as a stack canary, NX, PIE, full RELRO and FORTIFY, and
the presence of inherently unsafe libc imports (``strcpy``, ``gets``, ``system``,
``sprintf`` …) together with how many call sites reference each.

The adapter consumes a normalised, checksec-style JSON summary. In a live run
that summary is produced inside a local radare2 image (``rabin2 -I -i`` facts
folded into the schema below); offline, the recorded fixture feeds the SAME
:func:`parse`. Everything runs with ``--network none`` via the Docker runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# radare2 carries rabin2, which exposes the hardening + import facts this
# adapter folds into its checksec-style schema. Tag is a best-effort pin and may
# need bumping for a given host; a ghidra-headless image is the alternative.
IMAGE = "radare/radare2:5.9.8"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "binary" / "checksec.json"

# Each missing mitigation is a protection-mechanism failure (CWE-693). Severity
# reflects how load-bearing the mitigation is for memory-corruption defence.
_HARDENING = {
    "canary": ("stack canary", "high"),
    "nx": ("NX / no-execute stack", "high"),
    "pie": ("PIE / ASLR for the image", "medium"),
    "relro": ("full RELRO", "medium"),
    "fortify": ("FORTIFY_SOURCE", "low"),
}
# Inherently dangerous imports -> the weakness class their use most often yields.
_UNSAFE_IMPORT_CWE = {
    "gets": "CWE-242",      # use of inherently dangerous function
    "strcpy": "CWE-120", "strcat": "CWE-120", "sprintf": "CWE-120",
    "vsprintf": "CWE-120", "memcpy": "CWE-120", "scanf": "CWE-120",
    "system": "CWE-78", "popen": "CWE-78", "execl": "CWE-78",
}


def _hardening_disabled(key: str, value) -> bool:
    """True when a mitigation is absent or only partial."""
    if isinstance(value, bool):
        return not value
    v = str(value).strip().lower()
    if key == "relro":
        return v != "full"  # "no" / "partial" both count as not fully hardened
    return v in {"no", "false", "off", "none", "partial", "0", ""}


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {}
    out: List[Candidate] = []
    comp = data.get("target") or target
    n = 0

    hardening: Dict = data.get("hardening", {}) or {}
    for key, (label, severity) in _HARDENING.items():
        if key not in hardening:
            continue
        if not _hardening_disabled(key, hardening[key]):
            continue
        n += 1
        out.append(make_candidate(
            id=f"binary-{n}",
            title=f"Missing binary hardening: {label}",
            cwe="CWE-693",
            component=comp,
            severity=severity,
            description=(f"{label} is not enabled on {comp}; the binary is more "
                         "exposed to memory-corruption exploitation."),
            evidence=[f"checksec {key}={hardening[key]!r}", f"binary {comp}"],
            source_engine="static", tool="binary",
            rule=f"hardening/{key}", exploit_mitigation=key,
        ))

    for imp in data.get("unsafe_imports", []) or []:
        sym = (imp.get("symbol") or "").strip()
        if not sym:
            continue
        n += 1
        callsites = imp.get("callsites", 0)
        cwe = _UNSAFE_IMPORT_CWE.get(sym.lower(), "CWE-676")  # use of dangerous fn
        out.append(make_candidate(
            id=f"binary-{n}",
            title=f"Unsafe imported function: {sym}()",
            cwe=cwe,
            component=comp,
            severity="high" if cwe in {"CWE-78", "CWE-242"} else "medium",
            description=(f"{comp} imports {sym}() with {callsites} referencing "
                         "call site(s); this API is a frequent source of "
                         "memory-safety or injection defects."),
            evidence=[f"import {sym}", f"call sites: {callsites}"],
            source_engine="static", tool="binary",
            rule=f"unsafe-import/{sym}", callsites=callsites,
        ))
    return out


class BinaryDockerTool(DockerBackedTool):
    name = "binary"
    kind = ToolKind.STATIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # rabin2 reports headers/mitigations (-I) and imports (-i) as JSON; the
        # image folds that into the checksec-style schema :func:`parse` reads.
        return ["rabin2", "-I", "-i", "-j", self.container_workdir]


def make_docker() -> BinaryDockerTool:
    return BinaryDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("binary", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "BinaryDockerTool", "make_docker", "make_fixture"]
