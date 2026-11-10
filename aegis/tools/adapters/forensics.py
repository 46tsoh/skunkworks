"""Git-history forensics adapter (static) — mines secrets from the local clone.

This capability treats version-control history as an audit surface: credentials
that were committed (and often "deleted" in a later commit but still live in the
history), secrets re-introduced after an earlier cleanup, and security-relevant
commits. It is **host-local and read-only**: it runs ``gitleaks`` over the
*local clone only* via :func:`aegis.tools.runtime.run_local` (no container, no
network) and is gated on ``git`` being present on the host. Unlike the
Docker-backed scanners, there is no image to pull — the finding source is the
repository already on disk.

The same :func:`parse` feeds both the offline fixture adapter (a recorded
``gitleaks ... --report-format json`` document) and the live host adapter, so
the parser — the bug-prone part — is exercised with no binary and no network.
Every hit is normalised to a CWE-798 (Use of Hard-coded Credentials) candidate.
The raw secret value is never copied into a candidate; only its length and the
locating metadata (rule, file:line, commit) travel downstream.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import List, Optional, Sequence

from aegis.knowledge.models import Candidate
from aegis.tools import runtime
from aegis.tools.base import ToolKind, ToolResult, ToolStatus
from aegis.tools.util import make_candidate

# Host-local tool: no Docker image. gitleaks is distributed as a static binary
# and is run directly against the local clone. Recorded here for parity with the
# container-backed adapters' ``IMAGE`` symbol; see ``notes`` for the choice.
IMAGE: Optional[str] = None
GITLEAKS_RULEID_CWE = "CWE-798"  # Use of Hard-coded Credentials

_FIXTURE = (Path(__file__).resolve().parents[3]
            / "data" / "fixtures" / "forensics" / "gitleaks-report.json")


def _findings(data) -> list:
    """gitleaks writes a top-level JSON array; tolerate a wrapped object too."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "results", "Findings"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def parse(raw: str, target: str) -> List[Candidate]:
    """Turn a gitleaks JSON report into CWE-798 hard-coded-credential candidates.

    Tolerant of empty/blank input (returns ``[]``). Reads the ``RuleID``,
    ``File``/``StartLine``, ``Commit`` and ``Secret`` fields of each finding; the
    secret itself is redacted to a length so it never leaks into a candidate.
    """
    data = json.loads(raw) if raw.strip() else []
    out: List[Candidate] = []
    for i, f in enumerate(_findings(data)):
        if not isinstance(f, dict):
            continue
        rule = f.get("RuleID") or f.get("ruleID") or f"rule-{i}"
        path = f.get("File") or "?"
        line = f.get("StartLine", 0) or 0
        commit = (f.get("Commit") or "").strip()
        short_commit = commit[:10]
        desc = (f.get("Description") or rule).strip()
        secret = f.get("Secret") or f.get("Match") or ""
        where = f"commit {short_commit}" if short_commit else "working tree"
        out.append(make_candidate(
            id=f"forensics-{i+1}",
            title=f"Hard-coded secret in git history ({rule})"[:120],
            cwe=GITLEAKS_RULEID_CWE,
            component=f"{path}:{line}",
            severity="high",
            description=desc,
            evidence=[f"gitleaks rule {rule}", f"{path}:{line}", where,
                      f"redacted secret (len={len(secret)})"],
            source_engine="static", tool="forensics",
            rule=rule, commit=commit, author=f.get("Author"),
            date=f.get("Date"), fingerprint=f.get("Fingerprint"),
        ))
    return out


class ForensicsHostTool:
    """Host-local git-history secret scanner (no container).

    ``available()`` is true when ``git`` is on PATH (the minimum to have a local
    clone to mine); the live scan additionally shells out to ``gitleaks``.
    ``run()`` mirrors :class:`~aegis.tools.base.DockerBackedTool`: a missing
    binary degrades to ``UNAVAILABLE`` and any failure to ``ERROR`` — it never
    raises.
    """

    name = "forensics"
    kind = ToolKind.STATIC
    requires_binary = "git"
    scanner_binary = "gitleaks"
    timeout_s = 120.0

    def __init__(self, parser=parse) -> None:
        self._parser = parser

    def available(self) -> bool:
        return shutil.which(self.requires_binary) is not None

    def argv(self, target: str, **opts) -> Sequence[str]:
        # Scan the full history of the local clone and stream a JSON report to
        # stdout. ``detect`` walks commits; ``--no-git`` could scan a plain tree,
        # but forensics wants history, so we keep git mode. Local-only: gitleaks
        # performs no network I/O.
        return [self.scanner_binary, "detect",
                "--source", target,
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--redact", "--no-banner", "--exit-code", "0"]

    def run(self, target: str, **opts) -> ToolResult:
        t0 = time.perf_counter()
        if not self.available():
            return ToolResult(
                self.name, ToolStatus.UNAVAILABLE, target=target,
                errors=[f"{self.requires_binary!r} not found on PATH; install it "
                        "locally or use the fixture adapter"])
        try:
            cr = runtime.run_local(self.argv(target, **opts),
                                   timeout_s=self.timeout_s, cwd=target)
            raw = cr.stdout + (("\n[stderr]\n" + cr.stderr) if cr.stderr else "")
            cands = self._parser(cr.stdout, target)
            for c in cands:
                c.metadata.setdefault("tool", self.name)
            status = ToolStatus.OK if not cr.timed_out else ToolStatus.ERROR
            errors = ["timed out"] if cr.timed_out else []
            return ToolResult(
                self.name, status, candidates=cands, raw=raw, target=target,
                errors=errors,
                metadata={"exit": cr.exit_code,
                          "scanner": self.scanner_binary,
                          "scanner_present": shutil.which(self.scanner_binary) is not None},
                duration_ms=(time.perf_counter() - t0) * 1000.0)
        except Exception as exc:  # degrade, never raise
            return ToolResult(self.name, ToolStatus.ERROR, target=target,
                              errors=[f"{type(exc).__name__}: {exc}"],
                              duration_ms=(time.perf_counter() - t0) * 1000.0)


def make_host() -> ForensicsHostTool:
    """The live host adapter (runs gitleaks over the local clone)."""
    return ForensicsHostTool(parser=parse)


# Alias so callers that expect the Docker factory name still get a runnable tool.
make_docker = make_host


def make_fixture():
    from aegis.tools.base import FixtureTool
    return FixtureTool("forensics", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="git")


__all__ = [
    "IMAGE", "parse", "ForensicsHostTool", "make_host", "make_docker",
    "make_fixture",
]
