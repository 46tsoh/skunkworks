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

Live mechanics (mirrors CodeQL's scripted-driver pattern + ZAP's file report):

* A small Node/puppeteer driver (``docker/drivers/browser_navlog.js``) is
  mounted **read-only** into the container and run by overriding the image's
  entrypoint to ``node`` (the way CodeQL overrides its entrypoint to ``bash``).
* The target — a locally saved/served copy of the site — is mounted
  **read-only**; the driver loads it as a ``file://`` URL so a true live run
  needs no network (the default ``--network none`` holds).
* The driver drives the image's system Chromium (``--no-sandbox`` etc.),
  observes DOM sinks, mixed content and secrets, and writes the navigation-log
  JSON to a **writable report mount**; run() reads it back through the base
  class's hardened reader rather than trusting stdout.

The parser and its fixture are unchanged, so the offline suite pins the
detection logic byte-for-byte without Node, Chromium or any image present.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# Zenika's Alpine Chromium image, the ``-with-puppeteer`` variant: it bundles a
# system Chromium plus puppeteer-core wired to it, so the driver runs fully
# offline (no browser download). Best-effort public reference (verify/swap the
# tag against Docker Hub if a different local image is built); the parser — the
# tested contract — is unaffected by the tag. See docker/README.md.
IMAGE = "zenika/alpine-chrome:124-with-puppeteer"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "browser" / "navlog.json"
# The navigation-log driver, shipped in-repo and mounted read-only (below).
_DRIVER_SRC = Path(__file__).resolve().parents[3] / "docker" / "drivers" / "browser_navlog.js"


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
    # Local-only: the driver loads a file:// target from a read-only mount, so
    # no network grant is taken (the default --network none holds).
    container_workdir = "/aegis"
    # The image's entrypoint launches Chromium directly; override it to node so
    # we run our driver instead (as CodeQL overrides its entrypoint to bash).
    entrypoint = "node"
    # Mount points inside the container.
    DRIVER_SRC = _DRIVER_SRC
    # Mounted inside the image's app dir so Node resolves the bundled
    # puppeteer-core from the sibling /usr/src/app/node_modules (require()
    # resolution walks up from the script's directory, not the cwd).
    DRIVER_PATH = "/usr/src/app/aegis_navlog.js"   # driver script, mounted read-only
    INPUT_DIR = "/aegis/site"                 # saved/served site, mounted read-only
    # Chromium can only hand us the navigation log as a file; request a writable
    # report dir and read the JSON back from it (not stdout).
    REPORT_DIR = "/aegis/out"
    REPORT_FILE = "navlog.json"

    def report_mount(self):
        return (self.REPORT_DIR, self.REPORT_FILE)

    def mounts(self, target: str):
        # Always mount the driver read-only; mount the target read-only too when
        # it is a local path (the driver then loads it as file://). A bare URL
        # target mounts nothing extra (a live URL would need a network grant,
        # which this local-only adapter does not take).
        out = [(str(self.DRIVER_SRC), self.DRIVER_PATH)]
        p = Path(target)
        if p.is_file():
            # A single saved page: mount it as index.html so argv's
            # file://<INPUT_DIR>/index.html resolves (a file can't be the dir).
            out.append((str(p), f"{self.INPUT_DIR}/index.html"))
        elif p.exists():
            out.append((str(p), self.INPUT_DIR))
        return out

    def argv(self, target: str, **opts):
        # Run the driver under node (entrypoint override). It launches the image's
        # headless Chromium with the forwarded flags, visits the target and writes
        # the navigation-log JSON to the writable report mount, which run() reads
        # back. Default target is the read-only site mount loaded as file://.
        report = opts.get("report_path", f"{self.REPORT_DIR}/{self.REPORT_FILE}")
        url = opts.get("url")
        if not url:
            url = (f"file://{self.INPUT_DIR}/index.html"
                   if Path(target).exists() else target)
        return [self.DRIVER_PATH, "--target", url, "--out", report,
                "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]


def make_docker() -> BrowserDockerTool:
    return BrowserDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("browser", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "BrowserDockerTool", "make_docker", "make_fixture"]
