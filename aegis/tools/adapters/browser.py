"""Browser automation adapter (dynamic) — mines a headless navigation log.

This wraps a headless Chromium driver that loads the target's pages and records
what the client side actually does, then inspects that navigation log for issues
that only exist in the rendered page and its scripts:

* **DOM-XSS sinks** — a dangerous sink (``innerHTML``, ``document.write``,
  ``eval`` …) fed from an attacker-controllable source such as ``location.hash``
  (``CWE-79``).
* **Mixed content** — an HTTPS page pulling an active ``http://`` sub-resource,
  which an on-path attacker can tamper with (``CWE-319``, cleartext transmission).
* **Secrets in client JavaScript** — API keys or credentials shipped to the
  browser, where anyone can read them (``CWE-798``, hard-coded credentials).

The driver emits a navigation-log JSON (one record per visited page, with the
sinks, mixed-content resources and secret matches it observed, plus references
to the screenshot and saved page HTML). The same :func:`parse` feeds the offline
fixture adapter and the Docker-backed adapter, so the detection logic is pinned
without any browser binary or network. Running live stays local-only: the
container is launched through :mod:`aegis.tools.runtime` with ``--network none``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

IMAGE = "zenika/alpine-chrome:124"  # best-effort public tag; see module notes
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "browser" / "navlog.json"


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"pages": []}
    pages = data.get("pages", []) or []
    out: List[Candidate] = []
    n = 0

    for page in pages:
        page_url = page.get("url", "?")
        screenshot = page.get("screenshot", "")
        html = page.get("html", "")
        # Screenshot / saved-HTML references travel with each candidate as
        # evidence (base FixtureTool/DockerBackedTool do not build Artifacts).
        artifact_ev = [e for e in (f"screenshot {screenshot}" if screenshot else "",
                                   f"page html {html}" if html else "") if e]

        # 1) DOM-XSS sinks
        for s in page.get("dom_sinks", []) or []:
            sink = s.get("sink", "sink")
            source = s.get("source", "untrusted input")
            file = s.get("file", page_url)
            line = s.get("line", 0)
            n += 1
            out.append(make_candidate(
                id=f"browser-{n}",
                title=f"DOM-XSS sink {sink} fed from {source}",
                cwe="CWE-79",
                component=f"{file}:{line}",
                severity="high",
                description=(f"On {page_url}, {sink} receives data from {source} "
                             "without sanitisation, a DOM-based XSS sink."),
                evidence=[f"page {page_url}", s.get("snippet", f"{sink} <- {source}")]
                         + artifact_ev,
                source_engine="dynamic", tool="browser",
                kind="dom-xss-sink", sink=sink, page=page_url,
            ))

        # 2) mixed content (active http sub-resource on an https page)
        for m in page.get("mixed_content", []) or []:
            resource = m.get("resource", "?")
            rtype = m.get("type", "resource")
            n += 1
            out.append(make_candidate(
                id=f"browser-{n}",
                title=f"Mixed content: insecure {rtype} on HTTPS page",
                cwe="CWE-319",
                component=page_url,
                severity="medium",
                description=(f"{page_url} loads {rtype} over cleartext HTTP "
                             f"({resource}); an on-path attacker can tamper with it."),
                evidence=[f"page {page_url}", f"insecure {rtype} {resource}"]
                         + artifact_ev,
                source_engine="dynamic", tool="browser",
                kind="mixed-content", resource=resource,
            ))

        # 3) secrets exposed in client-side JavaScript
        for sec in page.get("secrets", []) or []:
            skind = sec.get("kind", "secret")
            match = sec.get("match", "")
            file = sec.get("file", page_url)
            line = sec.get("line", 0)
            redacted = (match[:4] + "***") if match else "***"
            n += 1
            out.append(make_candidate(
                id=f"browser-{n}",
                title=f"Secret in client JavaScript: {skind}",
                cwe="CWE-798",
                component=f"{file}:{line}",
                severity="high",
                description=(f"A {skind} is hard-coded in JavaScript served to the "
                             f"browser on {page_url}; client-side code is public."),
                evidence=[f"page {page_url}", f"{skind} {redacted}", f"{file}:{line}"]
                         + artifact_ev,
                source_engine="dynamic", tool="browser",
                kind="exposed-secret", secret_kind=skind,
            ))

    return out


class BrowserDockerTool(DockerBackedTool):
    name = "browser"
    kind = ToolKind.DYNAMIC
    image = IMAGE

    def argv(self, target: str, **opts):
        # The navigation-log JSON is produced by a driver script layered over
        # headless Chromium; the invocation below is best-effort (see module
        # notes). The fixture pins the parser.
        return ["chromium-browser", "--headless", "--no-sandbox",
                "--disable-gpu", "--dump-dom", target]


def make_docker() -> BrowserDockerTool:
    return BrowserDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("browser", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "BrowserDockerTool", "make_docker", "make_fixture"]
