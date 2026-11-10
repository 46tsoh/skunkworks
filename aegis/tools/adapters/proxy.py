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
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from aegis.knowledge.models import Candidate
from aegis.tools.base import DockerBackedTool, FixtureTool, ToolKind
from aegis.tools.util import make_candidate

IMAGE = "mitmproxy/mitmproxy:11.1.3"  # best-effort public tag; see module notes
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

    def argv(self, target: str, **opts):
        # Replay a recorded flow file and dump it as HAR to stdout. The live path
        # is best-effort (see module notes); the fixture pins the parser.
        flow = opts.get("flow", f"{self.container_workdir}/flows")
        return ["mitmdump", "--no-server", "-q", "-nr", flow,
                "--set", "hardump=-"]


def make_docker() -> ProxyDockerTool:
    return ProxyDockerTool(parser=parse)


def make_fixture() -> FixtureTool:
    return FixtureTool("proxy", ToolKind.DYNAMIC, _FIXTURE, parse,
                       requires_binary="docker")


__all__ = ["IMAGE", "parse", "ProxyDockerTool", "make_docker", "make_fixture"]
