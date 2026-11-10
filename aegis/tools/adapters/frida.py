"""Frida adapter (dynamic instrumentation) — parses a hook-trace JSON.

Frida injects a JavaScript agent into a *locally* launched process and reports,
via ``send()``, each time the process reaches an instrumented library call. The
Aegis agent script hooks a fixed set of dangerous sinks (command exec, SQL exec,
file open, raw memory writes, ...) and emits one JSON record per observed call,
flagging whether the arguments carried attacker-controlled (tainted) data. This
adapter turns that trace into :class:`Candidate` objects: one per *tainted* sink
call, since an untainted call to a dangerous function is not itself evidence of
a reachable vulnerability.

The same :func:`parse` feeds both the offline fixture adapter (a recorded trace)
and the Docker-backed adapter (runs Frida against a local process, no network).
Local-only: the container is launched with ``--network none`` by the runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

# Frida has no single canonical Docker Hub image; this is a best-effort public
# reference. See 'notes' — confirm/pin the tag (or build the agent image from
# docker/README.md) before relying on the live path. The fixture path is used
# in tests and needs no image.
IMAGE = "frida/frida:16.5.9"

_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "frida" / "hook-trace.json"

# The hook categories the agent script instruments, mapped to the weakness class
# the sink represents when its arguments are tainted. A hook may override this
# with an explicit ``cwe`` field (e.g. a buffer-write size mismatch).
_CATEGORY_CWE = {
    "command-exec": "CWE-78",    # OS command injection sink (system/popen/exec*)
    "sql-exec": "CWE-89",        # SQL executed from a tainted string
    "file-open": "CWE-22",       # path built from tainted input (traversal)
    "mem-write": "CWE-787",      # unbounded copy into a fixed buffer
    "deserialize": "CWE-502",    # untrusted data handed to a deserializer
    "env-read": "CWE-526",       # environment exposure (informational)
}


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"hooks": []}
    out: List[Candidate] = []
    n = 0
    for h in data.get("hooks", []) or []:
        # Only tainted sink calls are evidence; untainted calls are benign noise.
        if not h.get("tainted", False):
            continue
        n += 1
        fn = h.get("function", f"hook-{n}")
        module = h.get("module", "?")
        category = h.get("category", "")
        cwe = extract_cwe(h.get("cwe"), default=_CATEGORY_CWE.get(category, "CWE-693"))
        args = h.get("args", []) or []
        source = h.get("taint_source", "unknown source")
        backtrace = h.get("backtrace", []) or []
        evidence = [
            f"frida observed tainted call to {fn} ({category})",
            f"taint source: {source}",
        ]
        if args:
            evidence.append("args: " + " | ".join(str(a) for a in args)[:300])
        if backtrace:
            evidence.append("backtrace: " + " -> ".join(str(b) for b in backtrace))
        out.append(make_candidate(
            id=f"frida-{n}",
            title=f"Tainted {category or 'sink'} call to {fn}()",
            cwe=cwe,
            component=f"{module}!{fn}",
            severity=h.get("severity", "medium"),
            description=(f"Frida observed {fn}() reached at runtime with "
                         f"attacker-controlled input from {source}."),
            evidence=evidence,
            source_engine="dynamic", tool="frida",
            category=category, taint_source=source, backtrace=backtrace,
        ))
    return out


class FridaDockerTool(DockerBackedTool):
    name = "frida"
    kind = ToolKind.DYNAMIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # Spawn the target under Frida with the Aegis sink-hook agent, which
        # prints the hook-trace JSON to stdout. `target` is the program path
        # (mounted read-only at the container workdir).
        script = opts.get("script", "aegis-sink-hooks.js")
        return ["frida", "-q", "--runtime=v8", "-l", script, "-f", target]


def make_docker() -> FridaDockerTool:
    return FridaDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("frida", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "FridaDockerTool", "make_docker", "make_fixture"]
