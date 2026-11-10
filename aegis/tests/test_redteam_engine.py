"""Tests for the stage-1 exploit->verify engine (fake transport, no network)."""

from aegis.redteam import EngagementScope, RedTeamEngine
from aegis.redteam.http import HttpResponse, ScopeGatedTransport
from aegis.redteam.techniques import (
    MARKER, BooleanSQLi, OpenRedirect, ReflectedXSS, technique_for,
)


class FakeTransport:
    """Scripted transport: a handler(url, params) -> HttpResponse per call."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def send(self, method, url, params=None):
        self.calls.append((method, url, dict(params or {})))
        return self.handler(url, dict(params or {}))


def _scope(host="target.htb"):
    return EngagementScope(hosts=[host], urls=[f"http://{host}/"])


# -- technique routing -------------------------------------------------------
def test_technique_routing_by_cwe_and_keyword():
    assert isinstance(technique_for("CWE-79"), ReflectedXSS)
    assert isinstance(technique_for("sqli"), BooleanSQLi)
    assert isinstance(technique_for("open redirect"), OpenRedirect)
    assert technique_for("CWE-1234-unknown") is None


# -- reflected XSS -----------------------------------------------------------
def test_xss_verified_when_marker_reflected_in_html():
    def h(url, params):
        payload = params.get("q", "")
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            body=f"<html><body>hi {payload}</body></html>")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("xss", "http://target.htb/search", "q")
    assert r.verified and r.cwe == "CWE-79" and "reflected" in r.proof.lower()


def test_xss_not_verified_when_encoded():
    def h(url, params):
        # server HTML-encodes the payload → not exploitable
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            body="<html>hi &lt;svg/onload=...&gt;</html>")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("xss", "http://target.htb/search", "q")
    assert r.attempted and not r.verified


def test_xss_not_verified_when_reflected_in_json():
    def h(url, params):
        payload = params.get("q", "")
        return HttpResponse(url, 200, {"Content-Type": "application/json"},
                            body=f'{{"q": "{payload}"}}')
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("xss", "http://target.htb/api", "q")
    assert not r.verified  # reflected but not in an HTML context


# -- boolean / error SQLi ----------------------------------------------------
def test_sqli_verified_by_error_oracle():
    def h(url, params):
        v = params.get("id", "")
        if v.endswith("'"):
            return HttpResponse(url, 500, {}, "You have an error in your SQL syntax")
        return HttpResponse(url, 200, {}, "ok")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("CWE-89", "http://target.htb/item", "id")
    assert r.verified and "error" in " ".join(r.evidence).lower()


def test_sqli_verified_by_boolean_oracle():
    def h(url, params):
        v = params.get("id", "")
        if v.endswith("'1'='1"):      # TRUE → full page like baseline
            return HttpResponse(url, 200, {}, "ROW " * 200)
        if v.endswith("'1'='2"):      # FALSE → empty-ish page
            return HttpResponse(url, 200, {}, "none")
        return HttpResponse(url, 200, {}, "ROW " * 200)  # baseline
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("sqli", "http://target.htb/item", "id")
    assert r.verified and "boolean" in r.proof.lower()


def test_sqli_not_verified_when_stable():
    def h(url, params):
        return HttpResponse(url, 200, {}, "same page every time")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("sqli", "http://target.htb/item", "id")
    assert r.attempted and not r.verified


# -- open redirect -----------------------------------------------------------
def test_open_redirect_verified():
    def h(url, params):
        nxt = params.get("next", "")
        return HttpResponse(url, 302, {"Location": nxt}, "")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("redirect", "http://target.htb/go", "next")
    assert r.verified and r.cwe == "CWE-601"


def test_open_redirect_not_verified_when_sanitized():
    def h(url, params):
        return HttpResponse(url, 302, {"Location": "/safe/home"}, "")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("redirect", "http://target.htb/go", "next")
    assert not r.verified


# -- the load-bearing property: scope gating ---------------------------------
def test_out_of_scope_target_is_refused_without_any_request():
    sent = []

    def h(url, params):
        sent.append(url)
        return HttpResponse(url, 200, {"Content-Type": "text/html"}, "x")

    eng = RedTeamEngine(_scope("target.htb"), transport=FakeTransport(h))
    r = eng.attempt("xss", "http://not-in-scope.evil/search", "q")
    assert not r.in_scope and not r.attempted
    assert "out of scope" in r.note
    assert sent == []   # NOT A SINGLE REQUEST was sent off-scope


def test_scope_gated_transport_blocks_even_if_engine_check_bypassed():
    # Defense in depth: hit the transport directly with an out-of-scope URL.
    sent = []
    inner = FakeTransport(lambda u, p: sent.append(u) or HttpResponse(u, 200, {}, ""))
    gated = ScopeGatedTransport(inner, _scope("target.htb"))
    resp = gated.send("GET", "http://evil.example/x")
    assert not resp.ok and "out of scope" in resp.error
    assert sent == []


def test_events_emitted_for_audit():
    events = []
    def h(url, params):
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            body=f"<html>{params.get('q','')}</html>")
    eng = RedTeamEngine(_scope(), transport=FakeTransport(h),
                        on_event=events.append)
    eng.attempt("xss", "http://target.htb/s", "q")
    kinds = [e["event"] for e in events]
    assert "scope_check" in kinds and "exploit_start" in kinds \
        and "exploit_result" in kinds


def test_unknown_kind_is_not_attempted():
    eng = RedTeamEngine(_scope(), transport=FakeTransport(
        lambda u, p: HttpResponse(u, 200, {}, "")))
    r = eng.attempt("CWE-9999", "http://target.htb/x", "p")
    assert r.in_scope and not r.attempted and "no stage-1 technique" in r.note


# -- CLI gating --------------------------------------------------------------
def test_cli_exploit_refuses_without_authorized(capsys, tmp_path):
    import aegis.cli as cli
    sc = tmp_path / "s.json"
    sc.write_text('{"targets": {"urls": ["http://target.htb/"]}}')
    rc = cli.main(["exploit", "--target", "http://target.htb/x", "--param", "q",
                   "--type", "xss", "--scope", str(sc)])
    assert rc == 2
    assert "authorized" in capsys.readouterr().err.lower()


def test_cli_exploit_refuses_out_of_scope(capsys, tmp_path):
    import aegis.cli as cli
    sc = tmp_path / "s.json"
    sc.write_text('{"targets": {"urls": ["http://target.htb/"]}}')
    # in-scope host differs → refused before any network use
    rc = cli.main(["exploit", "--target", "http://evil.example/x", "--param",
                   "q", "--type", "xss", "--scope", str(sc), "--authorized"])
    assert rc == 2
    assert "out of scope" in capsys.readouterr().err.lower()


def test_cli_exploit_bad_scope_file(capsys, tmp_path):
    import aegis.cli as cli
    rc = cli.main(["exploit", "--target", "http://target.htb/x", "--param", "q",
                   "--type", "xss", "--scope", str(tmp_path / "nope.json"),
                   "--authorized"])
    assert rc == 2
    assert "scope error" in capsys.readouterr().err.lower()
