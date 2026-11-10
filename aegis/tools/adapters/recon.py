"""Recon adapter (dynamic surface map) — parses `nmap -oX` XML.

Builds a candidate per *open* TCP port discovered on the authorized local
target: each exposed service is a slice of attack surface and a potential
misconfiguration (unexpected service reachable, outdated banner). The same
:func:`parse` feeds both the offline fixture adapter (recorded XML) and the
Docker-backed adapter, which runs ``nmap`` inside a local, network-isolated
container against the bundled sample target only — never the internet.

Local-only: the Docker runtime forces ``--network none``, so a live scan can
only reach services mounted/reachable inside that sandbox, not external hosts.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from xml.etree import ElementTree as ET

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# nmap packaged on a minimal public image; pin a recent tag. See 'notes' re: tag.
IMAGE = "instrumentisto/nmap:7.94"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "recon" / "nmap.xml"


def _service_label(svc) -> str:
    """Human banner from an nmap <service> element (name/product/version)."""
    if svc is None:
        return "unknown"
    name = svc.get("name") or "unknown"
    product = svc.get("product")
    version = svc.get("version")
    banner = " ".join(p for p in (product, version) if p)
    return f"{name} ({banner})" if banner else name


def parse(raw: str, target: str) -> List[Candidate]:
    """Turn nmap XML into one candidate per open port. Tolerant of empty input."""
    if not raw.strip():
        return []
    # Harden the stdlib XML parser (no defusedxml dependency): nmap output never
    # declares a DTD or entities, so refuse any input that does — this blocks
    # XXE (external-entity) and billion-laughs expansion up front.
    lowered = raw.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("refusing XML with DTD/entity declarations")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # Malformed XML is surfaced as a parser error by the caller (-> ERROR).
        raise

    out: List[Candidate] = []
    n = 0
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else (target or "host")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue  # only open ports are live surface
            portid = port.get("portid", "0")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            label = _service_label(svc)
            n += 1
            out.append(make_candidate(
                id=f"recon-{n}",
                title=f"Exposed {label} service on {proto}/{portid}",
                # Exposed surface -> Information Exposure (CWE-200); low by default.
                cwe="CWE-200",
                component=f"{addr}:{portid}",
                severity="low",
                description=(f"nmap reports an open {proto}/{portid} port running "
                             f"{label} on {addr}."),
                evidence=[f"nmap open {proto}/{portid}", f"service: {label}"],
                source_engine="dynamic", tool="recon",
                port=portid, protocol=proto, service=(svc.get("name") if svc is not None else None),
            ))
    return out


class ReconDockerTool(DockerBackedTool):
    name = "recon"
    kind = ToolKind.DYNAMIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # -sV service/version detection, XML to stdout. Target is a host/IP the
        # caller authorized; defaults to loopback for the bundled sample.
        host = opts.get("host", "127.0.0.1")
        return ["nmap", "-sV", "-oX", "-", host]


def make_docker() -> ReconDockerTool:
    return ReconDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("recon", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ReconDockerTool", "make_docker", "make_fixture"]
