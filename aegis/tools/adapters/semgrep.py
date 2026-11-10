"""Semgrep adapter (static SAST) — parses `semgrep --json` output.

The same :func:`parse` feeds both the fixture adapter (offline, recorded output)
and the Docker-backed adapter (runs `semgrep/semgrep` locally, no network).

Offline rules: ``--config auto`` fetches rules from semgrep.dev, which is
unreachable under ``--network none``. Instead the OSS ``semgrep-rules`` ruleset
is provisioned once into a named volume (see docker/pull-images.sh), mounted
read-only here, and selected per language. Pointing at the whole repo aborts
(a rule-id collision across all dirs), so the adapter configures a curated set
of common-language rule directories that loads cleanly as one invocation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, Parser, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

IMAGE = "semgrep/semgrep:1.95.0"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "semgrep" / "results.json"


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"results": []}
    out: List[Candidate] = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        path = r.get("path", "?")
        line = (r.get("start", {}) or {}).get("line", 0)
        check = r.get("check_id", f"rule-{i}")
        out.append(make_candidate(
            id=f"semgrep-{i+1}",
            title=extra.get("message", check).strip().split("\n")[0][:120],
            cwe=extract_cwe(meta.get("cwe")),
            component=f"{path}:{line}",
            severity=extra.get("severity", "warning"),
            description=extra.get("message", ""),
            evidence=[f"semgrep rule {check}", f"{path}:{line}"],
            source_engine="static", tool="semgrep",
            rule=check, owasp_meta=meta.get("owasp"),
        ))
    return out


class SemgrepDockerTool(DockerBackedTool):
    name = "semgrep"
    kind = ToolKind.STATIC
    image = IMAGE
    ok_exit_codes = frozenset({0, 1})  # semgrep exits 1 when it finds matches
    timeout_s = 300.0  # compiling many rulesets takes a while
    # The OSS semgrep-rules ruleset, provisioned once into this read-only volume
    # (docker/pull-images.sh). Mounted at RULES_DIR; selected per language below.
    RULES_VOLUME = "aegis-semgrep-rules"
    RULES_DIR = "/rules"
    # Curated common-language rule dirs that load cleanly together (the full
    # repo aborts on a cross-dir rule-id collision). Broad SAST coverage.
    RULE_LANGS = ("python", "javascript", "typescript", "java", "go", "ruby",
                  "php", "c", "csharp", "generic", "bash", "html", "dockerfile",
                  "terraform", "yaml", "json")

    def volumes(self):
        return [(self.RULES_VOLUME, self.RULES_DIR)]

    def argv(self, target: str, **opts):
        # Offline by construction: local rule files only (never --config auto),
        # metrics off (no phone-home), scan everything in the read-only mount.
        config = opts.get("config")
        if config:
            cfg = ["--config", config]
        else:
            cfg = []
            for lang in self.RULE_LANGS:
                cfg += ["--config", f"{self.RULES_DIR}/{lang}"]
        return ["semgrep", *cfg, "--json", "--quiet", "--metrics=off",
                "--no-git-ignore", self.container_workdir]


def make_docker() -> SemgrepDockerTool:
    return SemgrepDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("semgrep", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "SemgrepDockerTool", "make_docker", "make_fixture"]
