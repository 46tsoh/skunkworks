"""HTTP intercept proxy adapter (dynamic) — mines intercepted traffic.

This wraps a man-in-the-middle proxy (mitmproxy) that records the requests and
responses a target emits while it is exercised, then inspects that recorded
traffic for issues that are only visible on the wire:

* **Reflected parameters** — a request query-parameter value that comes straight
  back in the response body, the classic precondition for reflected XSS
  (``CWE-79``).
* **Missing response security headers** — an HTML response served without a
  defence-in-depth header such as ``Content-Security-Policy`` (``CWE-693``,
  Protection Mechanism Failure).
* **Over-permissive CORS** — a response advertising
  ``Access-Control-Allow-Origin: *`` (``CWE-942``), doubly risky when paired with
  ``Access-Control-Allow-Credentials: true``.

The recorded traffic is read as a HAR document (HTTP Archive JSON), which is the
interchange format both mitmproxy and browsers export. The same :func:`parse`
feeds the offline fixture adapter and the Docker-backed adapter, so the parser —
the part that actually finds bugs — is pinned without any proxy binary or
network. Running live stays local-only: the container is launched through
:mod:`aegis.tools.runtime` with ``--network none`` and read-only mounts.

Live mechanics (mirrors ZAP's file-report pattern):

* The operator records traffic once with mitmproxy against an authorized target
  (``mitmdump -w flows`` — a one-time, out-of-band capture) and points the
  adapter at that recorded flow dump. The flow file is mounted **read-only**.
* At scan time the container replays the recording completely offline
  (``mitmdump -n -r`` — no proxy server is started, nothing touches the
  network) and mitmproxy's built-in ``hardump`` addon converts the flows to a
  HAR file in a **writable report mount** (see :meth:`DockerBackedTool.report_mount`).
  We read that file back through the base class's hardened reader rather than
  streaming HAR to stdout — ZAP taught us that a file report is the reliable
  path.

``hardump`` is built into mitmproxy 11+, so no addon script is mounted; the
offline fixture still pins the parser byte-for-byte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

# mitmproxy's maintained Docker Hub image. 11+ ships the built-in ``hardump``
# HAR addon this adapter relies on; pin a published 11.x tag. Best-effort public
# reference (verify/swap against Docker Hub if a different local image is built);
# the parser — the tested contract — is unaffected by the tag. See docker/README.md.
IMAGE = "mitmproxy/mitmproxy:11.1.3"
_FIXTURE = Path(__file__).resolve().parents[3] / "data" / "fixtures" / "proxy" / "flows.har"

# Defence-in-depth response headers we expect on an HTML response, in a fixed
# order so emitted candidates are deterministic. header -> human description.
_SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-content-type-options", "X-Content-Type-Options"),
]


def _headers(section: dict) -> dict:
    """Lower-cased header name -> value for one HAR request/response section."""
    out = {}
    for h in section.get("headers", []) or []:
        name = str(h.get("name", "")).strip().lower()
        if name:
            out[name] = h.get("value", "")
    return out


def _base_url(url: str) -> str:
    """Scheme+host+path with the query string dropped (a stable component id)."""
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _is_reflected(value: str, body: str) -> bool:
    """A query value is 'reflected' if it lands verbatim in the body and is
    distinctive enough (has markup characters, or is reasonably long) to be a
    real signal rather than an incidental substring match."""
    if not value or value not in body:
        return False
    if any(ch in value for ch in "<>\"'(){}"):
        return True
    return len(value) >= 8


def parse(raw: str, target: str) -> List[Candidate]:
    data = json.loads(raw) if raw.strip() else {"log": {"entries": []}}
    entries = (data.get("log", {}) or {}).get("entries", []) or []
    out: List[Candidate] = []
    n = 0

    for entry in entries:
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}
        url = req.get("url", "?")
        method = req.get("method", "GET")
        component = _base_url(url)
        resp_headers = _headers(resp)
        body = ((resp.get("content", {}) or {}).get("text", "")) or ""
        ctype = resp_headers.get("content-type", "")
        is_html = "html" in ctype.lower()

        # 1) reflected query parameters -> reflected-XSS precondition
        for q in req.get("queryString", []) or []:
            name = q.get("name", "")
            value = q.get("value", "")
            if _is_reflected(value, body):
                n += 1
                out.append(make_candidate(
                    id=f"proxy-{n}",
                    title=f"Reflected parameter '{name}' in response body",
                    cwe="CWE-79",
                    component=component,
                    severity="high",
                    description=(f"Value of query parameter '{name}' sent to "
                                 f"{method} {component} is reflected unencoded in "
                                 "the HTML response, enabling reflected XSS."),
                    evidence=[f"{method} {url}", f"param {name}={value}",
                              "value echoed in response body"],
                    source_engine="dynamic", tool="proxy",
                    param=name, kind="reflected-parameter",
                ))

        # 2) missing response security headers (HTML responses only)
        if is_html:
            for key, label in _SECURITY_HEADERS:
                if key not in resp_headers:
                    n += 1
                    out.append(make_candidate(
                        id=f"proxy-{n}",
                        title=f"Missing response header: {label}",
                        cwe="CWE-693",
                        component=component,
                        severity="low",
                        description=(f"HTML response from {component} omits the "
                                     f"{label} header, weakening browser-side "
                                     "defence in depth."),
                        evidence=[f"{method} {url}", f"missing {label}",
                                  f"content-type {ctype}"],
                        source_engine="dynamic", tool="proxy",
                        header=label, kind="missing-security-header",
                    ))

        # 3) over-permissive CORS
        acao = resp_headers.get("access-control-allow-origin", "")
        if acao.strip() == "*":
            creds = resp_headers.get("access-control-allow-credentials", "")
            with_creds = creds.strip().lower() == "true"
            n += 1
            out.append(make_candidate(
                id=f"proxy-{n}",
                title="Over-permissive CORS policy (Access-Control-Allow-Origin: *)",
                cwe="CWE-942",
                component=component,
                severity="high" if with_creds else "medium",
                description=(f"{component} returns a wildcard CORS origin"
                             + (" together with Access-Control-Allow-Credentials: "
                                "true, which browsers reject but signals a "
                                "reflected-origin misconfiguration risk."
                                if with_creds else ", exposing responses to any "
                                "origin.")),
                evidence=[f"{method} {url}", "Access-Control-Allow-Origin: *"]
                         + (["Access-Control-Allow-Credentials: true"] if with_creds else []),
                source_engine="dynamic", tool="proxy",
                kind="permissive-cors", with_credentials=with_creds,
            ))

    return out


class ProxyDockerTool(DockerBackedTool):
    name = "proxy"
    kind = ToolKind.DYNAMIC
    image = IMAGE
    # mitmdump replays the recording in-process and exits 0; replaying a file
    # never needs the network, so this adapter stays local-only (no
    # allows_network — the default --network none holds).
    container_workdir = "/aegis"
    # The recorded mitmproxy flow dump, mounted read-only (the operator captured
    # it out-of-band; it is the scan target, never written to).
    INPUT_FLOW = "/aegis/in/flows"
    # mitmproxy can only emit HAR to a file; request a fresh writable dir and
    # read the HAR back from it (like ZAP's JSON report), not from stdout.
    REPORT_DIR = "/aegis/out"
    REPORT_FILE = "flows.har"

    def report_mount(self):
        return (self.REPORT_DIR, self.REPORT_FILE)

    def mounts(self, target: str):
        # Mount the recorded flow dump read-only. The target is the path to the
        # operator's captured flows; a non-path target (e.g. a bare URL) mounts
        # nothing and the live replay has no input (degrades to no findings),
        # but the fixture/parser contract is unaffected.
        p = Path(target)
        if p.exists() and p.is_file():
            return [(str(p), self.INPUT_FLOW)]
        return []

    def argv(self, target: str, **opts):
        # Replay the read-only recording with no proxy server (``-n``: no
        # network), quietly, and let the built-in hardump addon write HAR to the
        # writable report mount. run() reads that file back and parses it.
        flow = opts.get("flow", self.INPUT_FLOW)
        report = opts.get("report_path", f"{self.REPORT_DIR}/{self.REPORT_FILE}")
        return ["mitmdump", "-n", "-q", "-r", flow,
                "--set", f"hardump={report}"]


def make_docker() -> ProxyDockerTool:
    return ProxyDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("proxy", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ProxyDockerTool", "make_docker", "make_fixture"]
