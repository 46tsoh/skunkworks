"""Git-history forensics adapter (static) — mines secrets from repo history.

This capability treats version-control history as an audit surface: credentials
that were committed (and often "deleted" later but still live in history),
secrets re-introduced after a cleanup, and security-relevant commits. It runs
``gitleaks`` **inside a local container** over the target repository mounted
**read-only**, with no network — so a hostile ``.git/config``, hook, or
``gitattributes`` in an untrusted target cannot execute on the host (the reason
this is containerised rather than run on the host).

The same :func:`parse` feeds the offline fixture adapter (a recorded
``gitleaks ... --report-format json`` document) and the live container adapter,
so the parser — the bug-prone part — is exercised with no binary and no network.
Every hit is normalised to a CWE-798 (Use of Hard-coded Credentials) candidate;
the raw secret value is never copied into a candidate (only its length and the
locating metadata travel downstream).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Sequence

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# Official gitleaks image. Pulled locally via docker/pull-images.sh; the adapter
# never pulls at scan time (runtime uses --pull=never).
IMAGE = "zricethezav/gitleaks:latest"
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

    Tolerant of empty/blank input (returns ``[]``). The secret itself is redacted
    to a length so it never leaks into a candidate.
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


class ForensicsDockerTool(DockerBackedTool):
    """gitleaks in a local container; target mounted read-only, no network.

    The target repo is read-only inside the container and the container has no
    network, so a malicious repo cannot execute on or exfiltrate from the host.
    """

    name = "forensics"
    kind = ToolKind.STATIC
    image = IMAGE
    requires_target_mount = True  # needs a repo on disk; empty mount -> ERROR

    def argv(self, target: str, **opts) -> Sequence[str]:
        # Entrypoint is `gitleaks`; scan the mounted repo history, redact secret
        # values in the report, and stream JSON to stdout. --exit-code 0 so a
        # "leaks found" run is not treated as a tool failure.
        return ["detect", "--source", self.container_workdir,
                "--report-format", "json", "--report-path", "/dev/stdout",
                "--redact", "--no-banner", "--exit-code", "0"]


def make_docker() -> ForensicsDockerTool:
    return ForensicsDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("forensics", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ForensicsDockerTool", "make_docker", "make_fixture"]
