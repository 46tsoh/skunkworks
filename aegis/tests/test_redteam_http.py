"""Tests for the red-team HTTP transport (mocked opener — no real network)."""

import io
import urllib.error

from aegis.redteam.http import (
    HttpResponse, ScopeGatedTransport, UrllibTransport, _with_query,
)
from aegis.redteam.scope import EngagementScope


def test_with_query_replaces_query_deterministically():
    assert _with_query("http://h/p?old=1", {"a": "b"}) == "http://h/p?a=b"
    assert _with_query("http://h/p", None) == "http://h/p"


def test_response_header_is_case_insensitive():
    r = HttpResponse("u", 200, {"Content-Type": "text/html"})
    assert r.header("content-type") == "text/html"
    assert r.header("missing") == ""


class _FakeResp(io.BytesIO):
    def __init__(self, body, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_urllib_transport_success(monkeypatch):
    t = UrllibTransport()
    monkeypatch.setattr(t._opener, "open",
                        lambda req, timeout: _FakeResp(b"<html>ok</html>", 200,
                                                       {"Content-Type": "text/html"}))
    r = t.send("GET", "http://target/x", {"q": "1"})
    assert r.ok and r.status == 200 and "ok" in r.body
    assert r.header("content-type") == "text/html"


def test_urllib_transport_httperror_still_usable(monkeypatch):
    t = UrllibTransport()

    def raise_http(req, timeout):
        raise urllib.error.HTTPError("http://target/x", 500, "err",
                                     {"X-K": "v"}, io.BytesIO(b"boom"))
    monkeypatch.setattr(t._opener, "open", raise_http)
    r = t.send("GET", "http://target/x")
    assert r.status == 500 and "boom" in r.body  # body/headers still captured


def test_urllib_transport_urlerror_is_error(monkeypatch):
    t = UrllibTransport()

    def raise_url(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(t._opener, "open", raise_url)
    r = t.send("GET", "http://target/x")
    assert not r.ok and "no route" in r.error and r.status == 0


def test_scope_gated_transport_passes_in_scope(monkeypatch):
    scope = EngagementScope(hosts=["target.htb"], urls=["http://target.htb/"])
    sent = []
    inner = type("T", (), {"send": lambda self, m, u, p=None: (
        sent.append(u) or HttpResponse(u, 200, {}, "ok"))})()
    gated = ScopeGatedTransport(inner, scope)
    r = gated.send("GET", "http://target.htb/x")
    assert r.ok and sent == ["http://target.htb/x"]


def test_scope_gated_transport_refuses_and_calls_on_refuse():
    scope = EngagementScope(hosts=["target.htb"])
    refused = []
    inner = type("T", (), {"send": lambda self, m, u, p=None: HttpResponse(u, 200, {}, "")})()
    gated = ScopeGatedTransport(inner, scope, on_refuse=refused.append)
    r = gated.send("GET", "http://evil.example/x")
    assert not r.ok and "out of scope" in r.error
    assert refused and refused[0].in_scope is False
