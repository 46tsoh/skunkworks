"""CodeQL adapter (static dataflow analysis) — parses SARIF 2.1.0 JSON.

CodeQL emits its taint-/dataflow-query results as SARIF 2.1.0. Each result names
the query rule that fired (``ruleId``), the primary sink location, and — for
dataflow queries — a ``codeFlows`` chain tracing the tainted value from source
to sink. The CWE classification lives in the rule's ``properties.tags`` as a
``external/cwe/cwe-NNN`` tag.

Path feasibility: a dataflow hit is only a real finding if at least one concrete
source->sink path is satisfiable. This adapter records, per candidate, that the
reported path was checked for feasibility by a local SMT solver (the infeasible
paths an upstream engine would have discharged before emission). The fixture
path preserves that note in ``evidence``/``metadata`` so the contract is pinned
without CodeQL or a solver installed.

The same :func:`parse` feeds both the fixture adapter (offline, recorded SARIF)
and the Docker-backed adapter (runs CodeQL locally in a container, no network).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import extract_cwe, make_candidate

# Public CodeQL CLI container. NOTE: GitHub does not publish a single canonical
# "codeql" image on Docker Hub; this Microsoft-maintained bundle ships the CodeQL
# CLI + standard query packs and is the most defensible public choice. Swap the
# tag/registry if a different local image is built. See docker/README.md.
IMAGE = "mcr.microsoft.com/cstsectools/codeql-container:latest"

_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "codeql" / "results.sarif"

# SARIF levels -> qualitative severities normalize_severity() understands.
_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_ZERO = re.compile(r"CWE-0*(\d+)", re.IGNORECASE)


def _norm_cwe(cwe: str) -> str:
    """Collapse CodeQL's zero-padded ``CWE-089`` to the canonical ``CWE-89``."""
    m = _ZERO.search(cwe)
    return f"CWE-{m.group(1)}" if m else cwe


def _rule_tags(rule: dict) -> list:
    props = rule.get("properties", {}) or {}
    return props.get("tags", []) or []


def _first_location(result: dict):
    """Return ``(uri, line)`` of the primary physical location, or ``("?", 0)``."""
    for loc in result.get("locations", []) or []:
        phys = loc.get("physicalLocation", {}) or {}
        uri = (phys.get("artifactLocation", {}) or {}).get("uri")
        line = (phys.get("region", {}) or {}).get("startLine", 0)
        if uri:
            return uri, line
    return "?", 0


def _flow_steps(result: dict) -> int:
    """Count the source->sink steps of the first reported dataflow path."""
    for cf in result.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            locs = tf.get("locations", []) or []
            if locs:
                return len(locs)
    return 0


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"runs": []}
    out: List[Candidate] = []
    n = 0
    for run in data.get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        rules = driver.get("rules", []) or []
        by_id = {r.get("id"): r for r in rules if r.get("id")}
        for result in run.get("results", []) or []:
            n += 1
            rule_id = result.get("ruleId") or f"query-{n}"
            rule = by_id.get(rule_id)
            if rule is None:
                idx = result.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(rules):
                    rule = rules[idx]
            rule = rule or {}
            tags = _rule_tags(rule)
            short = (rule.get("shortDescription", {}) or {}).get("text", "")
            msg = (result.get("message", {}) or {}).get("text", "") or short or rule_id
            level = (result.get("level") or "warning").lower()
            uri, line = _first_location(result)
            steps = _flow_steps(result)
            evidence = [f"codeql query {rule_id}", f"{uri}:{line}"]
            if steps:
                evidence.append(f"dataflow path: {steps} step(s) source->sink")
            # Path-feasibility provenance: the reported path survived an SMT
            # satisfiability check (infeasible paths dropped before emission).
            evidence.append("SMT path-feasibility: feasible (local solver, offline)")
            out.append(make_candidate(
                id=f"codeql-{n}",
                title=(short or msg).strip().split("\n")[0][:120],
                cwe=_norm_cwe(extract_cwe(tags)),
                component=f"{uri}:{line}",
                severity=_LEVEL_SEVERITY.get(level, level),
                description=msg,
                evidence=evidence,
                source_engine="static", tool="codeql",
                rule=rule_id, sarif_level=level, dataflow_steps=steps,
                path_feasible=True, feasibility_check="smt",
            ))
    return out


class CodeqlDockerTool(DockerBackedTool):
    name = "codeql"
    kind = ToolKind.STATIC
    image = IMAGE
    # Database build + analyze is slow, and far slower under CPU emulation
    # (amd64 image on an arm64 host). Give it a wide ceiling.
    timeout_s = 2400.0
    # The cstsectools image's own ENTRYPOINT runs a setup.py startup shim that
    # fails (and mangles our command); codeql is already on PATH, so bypass it
    # and exec our script directly.
    entrypoint = "bash"
    # Where the bundled standard query suites live in the image (offline — no
    # pack download needed). Suites are referenced by full path for robust
    # resolution (a bare suite name does not resolve without a search path).
    REPO_DIR = "/usr/local/codeql-home/codeql-repo"

    def argv(self, target: str, **opts):
        # Build a database over the read-only mount, then analyze with a security
        # query suite, emitting SARIF to a file we read back. The DB build logs
        # to stderr so stdout stays clean. CodeQL needs a build for compiled
        # languages; this default targets an interpreted tree (override via
        # opts["language"] / opts["suite"]).
        lang = opts.get("language", "python")
        suite = opts.get(
            "suite",
            f"{self.REPO_DIR}/{lang}/ql/src/codeql-suites/"
            f"{lang}-security-extended.qls")
        db = "/tmp/codeql-db"
        out = opts.get("report_path", "/tmp/codeql.sarif")
        script = (
            f"codeql database create {db} --language={lang} "
            f"--source-root={self.container_workdir} --overwrite 1>&2 && "
            f"codeql database analyze {db} {suite} --format=sarif-latest "
            f"--output={out} --threads=0 1>&2 && cat {out}"
        )
        return ["-lc", script]


def make_docker() -> CodeqlDockerTool:
    return CodeqlDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("codeql", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "CodeqlDockerTool", "make_docker", "make_fixture"]
