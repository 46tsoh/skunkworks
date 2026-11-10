"""Tests for the stage-1 PathTraversal (CWE-22) and SSTI (CWE-1336) techniques.

Offline only: a scripted fake transport returns crafted bodies — no Docker, no
network. These techniques are verify-only, read-only, and non-destructive. The
load-bearing properties checked here:

* positive confirm via a benign observable oracle,
* a *literal reflection* of the SSTI payload does NOT confirm (reflection
  immunity, mirroring CommandInjection's arithmetic oracle),
* a *signature-absent* traversal response does NOT confirm,
* the probe count stays tiny and bounded, and
* neither technique sets context that could trip the stage-2/3 gates (only a
  sequence-capable command-injection foothold drives those).
"""

from aegis.redteam import EngagementScope, RedTeamEngine
from aegis.redteam.techniques import (
    MARKER, PathTraversal, SSTI, _SSTI_SYNTAXES, technique_for,
)


class FakeTransport:
    """Scripted transport: a handler(url, params) -> HttpResponse per call."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def send(self, method, url, params=None):
        self.calls.append((method, url, dict(params or {})))
        return self.handler(url, dict(params or {}))


def _scope(host="target.htb", **kw):
    return EngagementScope(hosts=[host], urls=[f"http://{host}/"], **kw)


# -- technique routing -------------------------------------------------------
def test_routing_resolves_traversal_and_ssti():
    assert isinstance(technique_for("traversal"), PathTraversal)
    assert isinstance(technique_for("CWE-22"), PathTraversal)
    assert isinstance(technique_for("directory traversal"), PathTraversal)
    assert isinstance(technique_for("ssti"), SSTI)
    assert isinstance(technique_for("CWE-1336"), SSTI)
    assert isinstance(technique_for("server-side template injection"), SSTI)


# -- path traversal (CWE-22) -------------------------------------------------
def test_traversal_verified_when_benign_signature_reached():
    from aegis.redteam.http import HttpResponse

    def h(url, params):
        p = params.get("file", "")
        # server resolves ../ and serves the benign read-only file
        if "../" in p and p.endswith("etc/passwd"):
            return HttpResponse(url, 200, {}, "root:x:0:0:root:/root:/bin/bash\n")
        return HttpResponse(url, 404, {}, "not found")

    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("traversal", "http://target.htb/download", "file")
    assert r.verified and r.cwe == "CWE-22"
    assert "traversal confirmed" in r.proof.lower()
    assert any("signature" in e.lower() for e in r.evidence)


def test_traversal_not_verified_when_signature_absent():
    from aegis.redteam.http import HttpResponse

    def h(url, params):
        # app sanitises traversal → never serves the file
        return HttpResponse(url, 200, {}, "<html>invalid filename</html>")

    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("traversal", "http://target.htb/download", "file")
    assert r.attempted and not r.verified and r.proof == ""


def test_traversal_probe_count_is_tiny_and_bounded():
    from aegis.redteam.http import HttpResponse

    cap = len(PathTraversal._TRAVERSALS)
    # never-match handler → the technique exhausts its bounded probe set
    ft = FakeTransport(lambda u, p: HttpResponse(u, 404, {}, "no"))
    eng = RedTeamEngine(_scope(), transport=ft)
    r = eng.attempt("traversal", "http://target.htb/d", "file")
    assert not r.verified
    assert r.requests == cap and len(ft.calls) == cap
    assert cap <= 8   # "tiny" — a handful of depths, not a wordlist


def test_traversal_stops_at_first_confirming_depth():
    from aegis.redteam.http import HttpResponse

    # only the deepest traversal in the set reaches the file
    deepest = PathTraversal._TRAVERSALS[-1]

    def h(url, params):
        p = params.get("file", "")
        if p == deepest + "etc/passwd":
            return HttpResponse(url, 200, {}, "root:x:0:0:root:/root:/bin/sh\n")
        return HttpResponse(url, 404, {}, "no")

    ft = FakeTransport(h)
    eng = RedTeamEngine(_scope(), transport=ft)
    r = eng.attempt("traversal", "http://target.htb/d", "file")
    assert r.verified
    # it tried every depth up to and including the one that matched, then stopped
    assert len(ft.calls) == len(PathTraversal._TRAVERSALS)


def test_traversal_does_not_leak_file_contents_into_evidence():
    from aegis.redteam.http import HttpResponse

    secretish = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice"

    def h(url, params):
        return HttpResponse(url, 200, {}, secretish)

    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("traversal", "http://target.htb/d", "file")
    assert r.verified
    # the oracle reports only the fixed public signature, never other lines
    joined = " ".join(r.evidence) + " " + r.proof
    assert "alice" not in joined
    assert "/home/alice" not in joined


# -- SSTI (CWE-1336) ---------------------------------------------------------
def _ssti_product():
    return SSTI._A * SSTI._B


def test_ssti_verified_when_arithmetic_is_evaluated():
    from aegis.redteam.http import HttpResponse
    import re

    product = str(_ssti_product())

    def h(url, params):
        v = params.get("name", "")
        # emulate a template engine: evaluate any {{A*B}} it finds, strip braces
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", v)
        if m:
            v = v.replace(m.group(0), str(int(m.group(1)) * int(m.group(2))))
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            f"<html>Hello {v}</html>")

    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("ssti", "http://target.htb/greet", "name")
    assert r.verified and r.cwe == "CWE-1336"
    assert "template injection confirmed" in r.proof.lower()
    assert any(product in e for e in r.evidence)


def test_ssti_not_verified_on_literal_reflection():
    from aegis.redteam.http import HttpResponse

    product = str(_ssti_product())

    def h(url, params):
        # server reflects the payload VERBATIM (no evaluation) — the classic
        # false-positive trap. The literal `{{A*B}}` must not be mistaken for
        # execution.
        v = params.get("name", "")
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            f"<html>Hello {v}</html>")

    ft = FakeTransport(h)
    eng = RedTeamEngine(_scope(), transport=ft)
    r = eng.attempt("ssti", "http://target.htb/greet", "name")
    assert r.attempted and not r.verified and r.proof == ""
    # the raw payloads were reflected, but the evaluated product never appears
    bodies = [h(u, p).body for _, u, p in ft.calls]
    assert all(product not in b for b in bodies)


def test_ssti_marker_discipline_token_present_but_product_absent():
    from aegis.redteam.http import HttpResponse

    # Reflect the marker token but NOT an evaluated product: even though our
    # token round-trips, confirmation requires `token-<product>` contiguous.
    def h(url, params):
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            f"<html>{MARKER}ssti is here</html>")

    eng = RedTeamEngine(_scope(), transport=FakeTransport(h))
    r = eng.attempt("ssti", "http://target.htb/greet", "name")
    assert not r.verified


def test_ssti_probe_count_is_bounded_by_syntax_set():
    from aegis.redteam.http import HttpResponse

    ft = FakeTransport(lambda u, p: HttpResponse(u, 200, {}, "nope"))
    eng = RedTeamEngine(_scope(), transport=ft)
    r = eng.attempt("ssti", "http://target.htb/greet", "name")
    assert not r.verified
    assert r.requests == len(_SSTI_SYNTAXES) == len(ft.calls)
    assert len(_SSTI_SYNTAXES) <= 8   # tiny, bounded


# -- the staging contract: these are STAGE-1 ONLY ----------------------------
def test_traversal_never_triggers_stage2_or_stage3_even_when_allowed():
    from aegis.redteam.http import HttpResponse

    def h(url, params):
        return HttpResponse(url, 200, {}, "root:x:0:0:root:/root:/bin/bash")

    # Both escalation switches ON — only a sequence-capable cmdi foothold may
    # drive stages 2/3, so traversal must leave both untouched.
    scope = _scope(allow_post_exploit=True, allow_lateral=True, max_hosts=4)
    eng = RedTeamEngine(scope, transport=FakeTransport(h))
    r = eng.attempt("traversal", "http://target.htb/d", "file")
    assert r.verified
    assert r.post_exploit is None and r.lateral is None


def test_ssti_never_triggers_stage2_or_stage3_even_when_allowed():
    from aegis.redteam.http import HttpResponse
    import re

    def h(url, params):
        v = params.get("name", "")
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", v)
        if m:
            v = v.replace(m.group(0), str(int(m.group(1)) * int(m.group(2))))
        return HttpResponse(url, 200, {"Content-Type": "text/html"}, v)

    scope = _scope(allow_post_exploit=True, allow_lateral=True, max_hosts=4)
    eng = RedTeamEngine(scope, transport=FakeTransport(h))
    r = eng.attempt("ssti", "http://target.htb/greet", "name")
    assert r.verified
    assert r.post_exploit is None and r.lateral is None


def test_new_techniques_set_no_seq_context_key():
    # The stage-2/3 gates read context["seq"]; neither stage-1 technique may set
    # it (nor present technique == "cmdi"). Confirm directly on the VerifyResult.
    from aegis.redteam.http import HttpResponse

    def trav_h(url, params):
        return HttpResponse(url, 200, {}, "root:x:0:0:root")
    vt = PathTraversal().run(FakeTransport(trav_h), "http://t/", "file")
    assert vt.verified and "seq" not in vt.context and vt.technique != "cmdi"

    import re

    def ssti_h(url, params):
        v = params.get("x", "")
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", v)
        if m:
            v = v.replace(m.group(0), str(int(m.group(1)) * int(m.group(2))))
        return HttpResponse(url, 200, {}, v)
    vs = SSTI().run(FakeTransport(ssti_h), "http://t/", "x")
    assert vs.verified and "seq" not in vs.context and vs.technique != "cmdi"


# -- CLI choice wiring -------------------------------------------------------
def test_cli_exploit_accepts_traversal_and_ssti_types(tmp_path):
    import aegis.cli as cli
    sc = tmp_path / "s.json"
    sc.write_text('{"targets": {"urls": ["http://target.htb/"]}}')
    for typ in ("traversal", "ssti"):
        # out-of-scope target → rc 2 with "out of scope", which proves the
        # --type value parsed (an invalid choice would exit 2 at argparse with
        # a different message) and reached the scope gate.
        rc = cli.main(["exploit", "--target", "http://evil.example/x",
                       "--param", "q", "--type", typ, "--scope", str(sc),
                       "--authorized"])
        assert rc == 2


def test_cli_exploit_rejects_unknown_type(capsys, tmp_path):
    import aegis.cli as cli
    sc = tmp_path / "s.json"
    sc.write_text('{"targets": {"urls": ["http://target.htb/"]}}')
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["exploit", "--target", "http://target.htb/x", "--param", "q",
                  "--type", "not-a-real-type", "--scope", str(sc),
                  "--authorized"])
