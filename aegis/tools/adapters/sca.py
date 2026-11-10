"""SCA adapter (software composition analysis) — vulnerable/outdated deps.

Parses a Trivy-style filesystem scan report: a top-level ``Results[]`` array, one
entry per discovered manifest/lockfile, each carrying a ``Vulnerabilities[]``
list of advisories against installed packages. Each advisory names the package
(``PkgName``), the resolved version in the tree (``InstalledVersion``), the
advisory id (``VulnerabilityID`` — typically a CVE), a qualitative ``Severity``,
and often a ``FixedVersion`` and ``CweIDs``.

Every such hit is classified as the "vulnerable / outdated component" weakness
class, **CWE-1104** (Use of Unmaintained / Vulnerable Third-Party Components),
which maps cleanly to OWASP A06:2021. The advisory's own, finer-grained CWEs are
preserved in ``metadata``/``evidence`` for triage, but the candidate's class is
the dependency-risk class so the pipeline categorises it as a component issue
rather than, say, an injection bug that happens to live in a dependency.

The same :func:`parse` feeds both the fixture adapter (offline, recorded JSON)
and the Docker-backed adapter (runs Trivy locally, no network — vulnerability DB
must already be cached in the image/volume).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

IMAGE = "aquasec/trivy:0.58.1"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "sca" / "trivy.json"

# The dependency-risk weakness class every SCA hit is tagged with (-> OWASP A06).
VULN_COMPONENT_CWE = "CWE-1104"


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"Results": []}
    out: List[Candidate] = []
    n = 0
    for res in data.get("Results", []) or []:
        manifest = res.get("Target", "?")
        pkg_type = res.get("Type", "")
        for v in res.get("Vulnerabilities", []) or []:
            n += 1
            vid = v.get("VulnerabilityID", f"VULN-{n}")
            pkg = v.get("PkgName", "?")
            installed = v.get("InstalledVersion", "?")
            fixed = v.get("FixedVersion", "")
            severity = v.get("Severity", "medium")
            title = (v.get("Title") or f"{vid} in {pkg}").strip().split("\n")[0][:120]
            cwe_ids = v.get("CweIDs", []) or []
            evidence = [vid, f"{pkg} {installed}" + (f" (fixed in {fixed})" if fixed else " (no fix available)"),
                        f"manifest: {manifest}"]
            if cwe_ids:
                evidence.append("advisory CWEs: " + ", ".join(cwe_ids))
            out.append(make_candidate(
                id=f"sca-{n}",
                title=title,
                cwe=VULN_COMPONENT_CWE,
                component=f"{pkg}@{installed}",
                severity=severity,
                description=v.get("Description", title),
                evidence=evidence,
                source_engine="static", tool="sca",
                cve=vid, fixed_version=fixed or None, pkg_type=pkg_type,
                advisory_cwes=list(cwe_ids), manifest=manifest,
            ))
    return out


class ScaDockerTool(DockerBackedTool):
    name = "sca"
    kind = ToolKind.STATIC
    image = IMAGE
    timeout_s = 300.0
    # Trivy ships no vuln DB in the image and cannot download it under
    # --network none. The DB is provisioned once into a named volume (see
    # docker/pull-images.sh) that is mounted read-WRITE here: Trivy reads the DB
    # and writes its scan cache into the same cache dir. Nothing leaves the
    # volume; the scan itself still runs offline (--network none).
    CACHE_VOLUME = "aegis-trivy-cache"
    CACHE_DIR = "/root/.cache/trivy"

    def rw_volumes(self):
        return [(self.CACHE_VOLUME, self.CACHE_DIR)]

    def argv(self, target: str, **opts):
        # Scan the read-only mount as a filesystem target, vuln scanner only,
        # JSON to stdout. --skip-db-update + --offline-scan guarantee no network
        # (the DB is already in the mounted cache); --cache-dir points at it.
        return ["fs", "--format", "json", "--quiet", "--scanners", "vuln",
                "--skip-db-update", "--offline-scan",
                "--cache-dir", self.CACHE_DIR, self.container_workdir]


def make_docker() -> ScaDockerTool:
    return ScaDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("sca", ToolKind.STATIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "VULN_COMPONENT_CWE", "ScaDockerTool",
           "make_docker", "make_fixture"]
