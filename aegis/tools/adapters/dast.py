"""DAST adapter (dynamic) — parses an OWASP ZAP JSON report.

ZAP probes authorized endpoints (injection, traversal, header/config
weaknesses) and writes a JSON report whose findings live under
``site[].alerts[]``. Each alert becomes a candidate; a candidate's component is
the first probed instance URI, and its CWE/severity come straight from the
alert. The same :func:`parse` feeds the offline fixture adapter (recorded JSON)
and the Docker-backed adapter, which runs a ZAP container against the target.

Two scan depths, selected per run:

* **baseline** (default, ``zap-baseline.py``) — spiders the target and runs
  ZAP's *passive* rules only. It never sends attack payloads, so it is safe to
  point at any authorized host and finishes in well under a minute.
* **active** (``--active`` → ``zap-full-scan.py``) — spiders, then runs the
  *active* scanner, which sends real attack payloads (SQLi, XSS, traversal…) to
  exercise each parameter. It is intrusive and slow, so it is opt-in and, like
  every ``aegis scan``, gated behind ``--authorized``: only run it against a
  target you own or a public test range you are permitted to attack.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# ZAP's maintained Docker image (ZAP project). See 'notes' re: tag/registry.
IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
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
                # Persist the attacked parameter/method STRUCTURALLY (not only
                # in free-text evidence) so the autonomous agent can auto-target
                # a stage-1 exploit from this finding without scraping strings.
                param=first.get("param") or None,
                method=first.get("method") or None,
            ))
    return out


class ZapDockerTool(DockerBackedTool):
    name = "dast"
    allows_network = True  # remote DAST scanner (ZAP)
    kind = ToolKind.DYNAMIC
    image = IMAGE
    # The active scanner spiders then attacks every parameter; that is slow, so
    # give the container room (baseline finishes far inside this ceiling).
    timeout_s = 600.0
    # Run in the report dir: ZAP's automation framework resolves the report path
    # relative to this working dir, so we pass a bare filename (an absolute path
    # gets the working dir prepended → /zap/wrk/zap/wrk/...).
    container_workdir = "/zap/wrk"
    # ZAP exits non-zero to signal WARN/FAIL-level alerts, not just real
    # failures; a report is still produced in those cases, so accept them.
    ok_exit_codes = frozenset({0, 1, 2})
    # ZAP can only write its JSON report to a file, and that file must live in a
    # mounted directory — it refuses otherwise. We mount a fresh writable dir at
    # its working path and read the report back from it (see DockerBackedTool).
    REPORT_DIR = "/zap/wrk"
    REPORT_FILE = "aegis-zap.json"

    def report_mount(self):
        return (self.REPORT_DIR, self.REPORT_FILE)

    def argv(self, target: str, **opts):
        # Target URL is caller-authorized. ``-I`` keeps a non-zero "warnings
        # present" exit from failing the run; ``-J`` writes the JSON report to
        # the mounted report path (run() reads it back and parses it).
        #   active=False → zap-baseline.py: spider + PASSIVE rules only, no
        #                  attack payloads sent (safe, fast).
        #   active=True  → zap-full-scan.py: spider + ACTIVE scanner, which
        #                  sends real attack payloads (intrusive, authorized).
        url = opts.get("url", target)
        # Bare filename: ZAP resolves -J relative to its working dir (REPORT_DIR,
        # the writable mount), so the report lands where run() reads it back.
        if opts.get("active"):
            # Bound the spider and active scanner so a run always completes
            # inside timeout_s (an unbounded active scan of a large app would
            # otherwise time out and surface no findings). Overridable via opts.
            zap_opts = opts.get("zap_options") or (
                f"-config spider.maxDuration={opts.get('spider_mins', 2)} "
                f"-config scanner.maxScanDurationInMins="
                f"{opts.get('scan_mins', 5)}")
            return ["zap-full-scan.py", "-t", url, "-J", self.REPORT_FILE,
                    "-I", "-z", zap_opts]
        return ["zap-baseline.py", "-t", url, "-J", self.REPORT_FILE, "-I"]


def make_docker() -> ZapDockerTool:
    return ZapDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("dast", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ZapDockerTool", "make_docker", "make_fixture"]
