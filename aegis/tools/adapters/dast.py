"""DAST adapter (dynamic) — parses an OWASP ZAP JSON report.

ZAP actively probes authorized endpoints (injection, traversal, header/config
weaknesses) and writes a JSON report whose findings live under
``site[].alerts[]``. Each alert becomes a candidate; a candidate's component is
the first probed instance URI, and its CWE/severity come straight from the
alert. The same :func:`parse` feeds the offline fixture adapter (recorded JSON)
and the Docker-backed adapter, which runs a ZAP container locally and
network-isolated against the authorized sample target only.

Local-only: the Docker runtime forces ``--network none``; active probes reach
only endpoints inside that sandbox, never the public internet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# ZAP's maintained Docker image (ZAP project). See 'notes' re: tag/registry.
IMAGE = "zaproxy/zaproxy:stable"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "dast" / "zap.json"

# ZAP riskcode -> qualitative severity (0 info, 1 low, 2 medium, 3 high).
_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def parse(raw: str, target: str) -> List[Candidate]:
    """Turn a ZAP JSON report into candidates. Tolerant of empty input."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    out: List[Candidate] = []
    n = 0
    for site in data.get("site", []) or []:
        site_name = site.get("@name") or site.get("name") or (target or "?")
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or []
            first = instances[0] if instances else {}
            uri = first.get("uri") or site_name
            severity = _RISK.get(str(alert.get("riskcode", "")), None) \
                or alert.get("riskdesc", "medium").split(" ")[0].lower()
            cweid = str(alert.get("cweid", "")).strip()
            cwe = f"CWE-{cweid}" if cweid.isdigit() and cweid != "0" else "CWE-693"
            name = alert.get("alert") or alert.get("name") or "ZAP alert"
            pluginid = str(alert.get("pluginid", n))
            n += 1
            evidence = [f"zap plugin {pluginid}", f"{first.get('method', 'GET')} {uri}"]
            if first.get("param"):
                evidence.append(f"param: {first['param']}")
            if first.get("evidence"):
                evidence.append(f"evidence: {first['evidence']}")
            out.append(make_candidate(
                id=f"dast-{n}",
                title=str(name)[:120],
                cwe=cwe,
                component=str(uri),
                severity=severity,
                description=f"ZAP alert {name!r} (plugin {pluginid}) on {site_name}.",
                evidence=evidence,
                source_engine="dynamic", tool="dast",
                pluginid=pluginid, site=site_name,
            ))
    return out


class ZapDockerTool(DockerBackedTool):
    name = "dast"
    allows_network = True  # remote DAST scanner (ZAP)
    kind = ToolKind.DYNAMIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # ZAP baseline scan writing a JSON report to stdout-friendly path.
        # Target URL is caller-authorized; no internet reach (network none).
        url = opts.get("url", target)
        return ["zap-baseline.py", "-t", url, "-J", "/dev/stdout", "-I"]


def make_docker() -> ZapDockerTool:
    return ZapDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("dast", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ZapDockerTool", "make_docker", "make_fixture"]
