"""HTTP transport for the red-team engine — scope-gated, bounded, stdlib-only.

Every request the engine makes goes through a :class:`Transport`. The live
:class:`UrllibTransport` is deliberately minimal and safe: a tight timeout, a
capped response read, no auto-redirect (the engine inspects ``Location``
itself), no cookies or credentials, and a generic User-Agent (the user's
identity is never leaked to a target).

:class:`ScopeGatedTransport` wraps any transport and **refuses to send to a URL
that is not in the engagement scope** — a second, independent enforcement of the
authorization gate on top of the engine's own check (defense in depth). There is
no way to reach the network except through a scope-gated transport.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol
from urllib.parse import urlencode, urlparse, urlunparse

from aegis.redteam.scope import EngagementScope, ScopeError

# Hard caps so a probe can never become a resource hog or a DoS.
_TIMEOUT_S = 15.0
_MAX_BYTES = 2 * 1024 * 1024  # 2 MiB of response is plenty to verify a marker
_USER_AGENT = "aegis-redteam/1.0"   # generic; never the operator's identity


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and 0 < self.status < 600

    def header(self, name: str) -> str:
        """Case-insensitive header lookup."""
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return ""


class Transport(Protocol):
    def send(self, method: str, url: str,
             params: Optional[Dict[str, str]] = None) -> HttpResponse: ...


def _with_query(url: str, params: Optional[Dict[str, str]]) -> str:
    if not params:
        return url
    parts = urlparse(url)
    # Replace the query entirely with the probe params (deterministic probes).
    return urlunparse(parts._replace(query=urlencode(params)))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects — we inspect Location ourselves (open-redirect
    verification), and following could leave the authorized scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Live HTTP via stdlib urllib. Bounded and credential-free by design."""

    def __init__(self, timeout_s: float = _TIMEOUT_S) -> None:
        self.timeout_s = timeout_s
        self._opener = urllib.request.build_opener(_NoRedirect)

    def send(self, method: str, url: str,
             params: Optional[Dict[str, str]] = None) -> HttpResponse:
        full = _with_query(url, params)
        req = urllib.request.Request(full, method=method.upper(),
                                     headers={"User-Agent": _USER_AGENT})
        try:
            with self._opener.open(req, timeout=self.timeout_s) as resp:
                raw = resp.read(_MAX_BYTES)
                body = raw.decode("utf-8", errors="replace")
                headers = {k: v for k, v in resp.headers.items()}
                return HttpResponse(full, resp.status, headers, body)
        except urllib.error.HTTPError as exc:
            # A 3xx/4xx/5xx is still a usable response (status + headers + body).
            try:
                body = exc.read(_MAX_BYTES).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            headers = {k: v for k, v in (exc.headers or {}).items()}
            return HttpResponse(full, exc.code, headers, body)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return HttpResponse(full, 0, {}, "", error=str(exc))


class ScopeGatedTransport:
    """Wrap a transport so a request to an out-of-scope URL is never sent.

    This is independent of the engine's own scope check — the network is only
    ever reachable through here, so a bug that skipped the engine check still
    cannot send out of scope. Out-of-scope sends return an error response (and
    invoke ``on_refuse`` for the audit log); they never reach the wire.
    """

    def __init__(self, inner: Transport, scope: EngagementScope,
                 on_refuse=None) -> None:
        self._inner = inner
        self._scope = scope
        self._on_refuse = on_refuse

    def send(self, method: str, url: str,
             params: Optional[Dict[str, str]] = None) -> HttpResponse:
        full = _with_query(url, params)
        decision = self._scope.check(full)
        if not decision.in_scope:
            if self._on_refuse:
                self._on_refuse(decision)
            return HttpResponse(full, 0, {}, "",
                                error=f"refused: out of scope ({decision.reason})")
        return self._inner.send(method, url, params)


__all__ = ["HttpResponse", "Transport", "UrllibTransport", "ScopeGatedTransport",
           "ScopeError"]
