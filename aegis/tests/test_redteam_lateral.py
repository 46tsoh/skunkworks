"""Stage-3 lateral-movement tests — the load-bearing rule: scope never expands.

A fake foothold runner stands in for command execution on the compromised host:
`cat /etc/hosts` returns a planted host list, and `curl <url>` returns a planted
page per URL. No real execution, no network.
"""

import json

from aegis.redteam import EngagementScope, RedTeamEngine
from aegis.redteam.lateral import discover_hosts, move_laterally
from aegis.redteam.http import HttpResponse


def make_runner(hosts_file="", pages=None):
    """Return (run_cmd, calls). run_cmd emulates foothold command output."""
    pages = pages or {}
    calls = []

    def run_cmd(cmd):
        calls.append(cmd)
        if cmd == "cat /etc/hosts":
            return hosts_file
        if cmd.startswith("curl "):
            url = cmd.split()[-1].strip("'")
            return pages.get(url)
        return ""
    return run_cmd, calls


def _scope(urls, hosts=None, **kw):
    return EngagementScope(hosts=hosts or [], urls=urls, **kw)


# -- discovery is read-only data ---------------------------------------------
def test_discover_parses_etc_hosts():
    run_cmd, _ = make_runner(
        "127.0.0.1 localhost\n10.0.0.5 target-b internal\n# comment\n")
    hosts = discover_hosts(run_cmd)
    assert "10.0.0.5" in hosts and "target-b" in hosts and "localhost" in hosts


# -- THE load-bearing property: no auto-expand -------------------------------
def test_discovered_out_of_scope_host_is_refused_never_touched():
    # /etc/hosts reveals evil.internal, but it is NOT in scope → must be refused
    # and never curled.
    run_cmd, calls = make_runner(
        hosts_file="10.0.0.5 target-b\n66.66.66.66 evil.internal\n",
        pages={"http://10.0.0.9:8100/": "page B"})
    scope = _scope(urls=["http://10.0.0.9:8100/"])   # the only in-scope target
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    assert "evil.internal" in res.refused_out_of_scope
    # no curl was ever issued to the out-of-scope host
    assert not any("evil.internal" in c or "66.66.66.66" in c for c in calls)
    # only the in-scope scope url was pivoted to
    assert [p.url for p in res.pivots] == ["http://10.0.0.9:8100/"]


def test_pivot_targets_come_only_from_scope_urls():
    # discovery lists many hosts; actionable pivots are ONLY scope.urls (minus origin)
    run_cmd, _ = make_runner(
        hosts_file="1.2.3.4 a\n5.6.7.8 b\n",
        pages={"http://10.0.0.9:8100/": "B page FLAG{pivot}"})
    scope = _scope(urls=["http://10.0.0.9:8100/"], hosts=["1.2.3.4", "5.6.7.8"])
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    assert [p.url for p in res.pivots] == ["http://10.0.0.9:8100/"]
    assert res.pivots[0].reachable and res.pivots[0].flag == "FLAG{pivot}"


def test_origin_host_is_not_a_pivot_target():
    run_cmd, _ = make_runner(pages={"http://10.0.0.9/": "other"})
    scope = _scope(urls=["http://10.0.0.1/", "http://10.0.0.9/"])
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    hosts = [p.host for p in res.pivots]
    assert "10.0.0.1" not in hosts and "10.0.0.9" in hosts


# -- max_hosts bound (never silent) ------------------------------------------
def test_max_hosts_caps_and_logs():
    urls = [f"http://10.0.0.{i}/" for i in range(10, 16)]   # 6 targets
    run_cmd, _ = make_runner(pages={u: "x" for u in urls})
    scope = _scope(urls=urls)
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=2)
    assert len(res.pivots) == 2
    assert len(res.capped) == 4            # the rest are logged, not silently dropped


# -- engine gating -----------------------------------------------------------
def make_cmdi_engine_transport(fs_pages):
    """A transport that emulates a cmdi foothold whose shell can curl in-scope
    hosts. fs_pages maps a curl'd URL to its page body."""
    from aegis.redteam.techniques import MARKER
    import re
    A, B = 1337, 7919
    product = A * B

    def evaluate(v):
        # confirm arithmetic oracle
        s = v.replace(f"$(({A}*{B}))", str(product))
        out = []
        for tok in re.split(r";|\n|&&|\|", s):
            t = tok.strip()
            if t.startswith("echo "):
                out.append(t[5:])
            elif t == "id":
                out.append("uid=0(root)")
            elif t.startswith("uname"):
                out.append("Linux")
            elif t.startswith("cat "):
                pass
            elif t.startswith("curl"):
                url = t.split()[-1].strip("'")
                out.append(fs_pages.get(url, ""))
        return "\n".join(out)

    class T:
        def send(self, m, url, params=None):
            v = (params or {}).get("p", "")
            body = "\n" + evaluate(v[1:]) if v.startswith("x") else ""
            return HttpResponse(url, 200, {"Content-Type": "text/plain"}, body)
    return T()


def test_engine_runs_lateral_only_when_allowed():
    t = make_cmdi_engine_transport({"http://10.0.0.9:8100/": "hi FLAG{lateral}"})
    scope = EngagementScope(hosts=["10.0.0.1", "10.0.0.9"],
                            urls=["http://10.0.0.1:80/", "http://10.0.0.9:8100/"],
                            allow_post_exploit=True, allow_lateral=True, max_hosts=4)
    eng = RedTeamEngine(scope, transport=t)
    r = eng.attempt("cmdi", "http://10.0.0.1:80/app", "p")
    assert r.verified and r.lateral and r.lateral["ran"]
    flags = [p["flag"] for p in r.lateral["pivots"] if p["flag"]]
    assert "FLAG{lateral}" in flags


def test_engine_skips_lateral_when_scope_disallows():
    t = make_cmdi_engine_transport({"http://10.0.0.9:8100/": "hi"})
    scope = EngagementScope(hosts=["10.0.0.1", "10.0.0.9"],
                            urls=["http://10.0.0.1:80/", "http://10.0.0.9:8100/"],
                            allow_post_exploit=True, allow_lateral=False, max_hosts=4)
    eng = RedTeamEngine(scope, transport=t)
    r = eng.attempt("cmdi", "http://10.0.0.1:80/app", "p")
    assert r.verified and r.lateral is None         # stage 3 never ran
    assert "lateral off" in r.note


def test_lateral_requires_cmdi_foothold():
    # a verified XSS (no shell) must never trigger lateral movement
    class XSST:
        def send(self, m, u, params=None):
            return HttpResponse(u, 200, {"Content-Type": "text/html"},
                                f"<html>{params.get('q','')}</html>")
    scope = EngagementScope(hosts=["t.htb"], urls=["http://t.htb/"],
                            allow_lateral=True, max_hosts=4)
    eng = RedTeamEngine(scope, transport=XSST())
    r = eng.attempt("xss", "http://t.htb/s", "q")
    assert r.verified and r.lateral is None


# -- unsafe pivot url is not executed ----------------------------------------
def test_unsafe_scope_url_is_not_curled():
    run_cmd, calls = make_runner(pages={})
    # a scope url with a space / shell metachar must not be spliced into curl
    scope = _scope(urls=["http://10.0.0.9/;id", "http://10.0.0.9/"])
    # note: the in-scope check still applies; the unsafe one is skipped by _safe_url
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    assert not any(";id" in c for c in calls)


def test_pivot_page_without_trailing_newline_is_captured():
    # regression (found by live-fire): a page with NO trailing newline put the
    # end marker on the page's last line; the extractor must still capture it.
    page = "<html>B - FLAG{no_newline}</html>"   # no trailing \n
    t = make_cmdi_engine_transport({"http://10.0.0.9:8100/": page})
    scope = EngagementScope(hosts=["10.0.0.1", "10.0.0.9"],
                            urls=["http://10.0.0.1:80/", "http://10.0.0.9:8100/"],
                            allow_post_exploit=True, allow_lateral=True, max_hosts=4)
    r = RedTeamEngine(scope, transport=t).attempt("cmdi", "http://10.0.0.1:80/a", "p")
    pivots = r.lateral["pivots"]
    assert pivots[0]["reachable"] and pivots[0]["flag"] == "FLAG{no_newline}"


# -- findings from the adversarial security review ---------------------------
def test_acted_on_host_never_also_refused_url_only_scope():
    # #1/#2: an in-scope pivot host declared only via scope.urls that ALSO
    # appears in /etc/hosts must NOT be mislabelled refused-out-of-scope.
    run_cmd, _ = make_runner(
        hosts_file="10.0.0.9 pivot-c\n66.66.66.66 evil\n",
        pages={"http://10.0.0.9:8100/": "B FLAG{x}"})
    scope = _scope(urls=["http://10.0.0.9:8100/"], hosts=[])   # url-only
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    acted = {p.host for p in res.pivots}
    assert "10.0.0.9" in acted
    # disjointness invariant: nothing acted on is in the refused list
    assert not (acted & set(res.refused_out_of_scope))
    assert "10.0.0.9" not in res.refused_out_of_scope   # the acted-on host
    assert "evil" in res.refused_out_of_scope           # genuinely out of scope
    # ('pivot-c', an unresolved /etc/hosts alias for the in-scope IP, is still
    #  refused — we never DNS-resolve, and we never act on that name, so there
    #  is no contradiction: the acted-on host is the IP, which is not refused.)


def test_in_scope_but_unsafe_url_is_skipped_and_noted():
    # #4: an in-scope url containing a single-quote must be skipped (never
    # curled) and surfaced in the note.
    run_cmd, calls = make_runner(pages={"http://10.0.0.9/ok": "ok"})
    scope = _scope(urls=["http://10.0.0.9/a'b", "http://10.0.0.9/ok"])
    res = move_laterally(scope, run_cmd, origin_host="10.0.0.1", max_hosts=8)
    assert "skipped-unsafe-url" in res.note
    assert not any("a'b" in c for c in calls)          # the unsafe url is never run
    assert [p.url for p in res.pivots] == ["http://10.0.0.9/ok"]


def test_seq_false_cmdi_foothold_no_lateral(monkeypatch):
    # #5/#6: a substitution-only (seq=False) cmdi foothold must NOT pivot.
    import aegis.redteam.techniques as tq
    from aegis.redteam.techniques import VerifyResult
    monkeypatch.setattr(tq.CommandInjection, "run",
                        lambda self, transport, url, param: VerifyResult(
                            True, "cmdi", "CWE-78", "sub-only", ["$(...)"],
                            requests=1, context={"template": "$({cmd})",
                                                 "seq": False, "param": param}))
    scope = EngagementScope(hosts=["10.0.0.1", "10.0.0.9"],
                            urls=["http://10.0.0.1/", "http://10.0.0.9/"],
                            allow_lateral=True, max_hosts=4)
    eng = RedTeamEngine(scope, transport=make_cmdi_engine_transport({}))
    r = eng.attempt("cmdi", "http://10.0.0.1/a", "p")
    assert r.verified and r.lateral is None


def test_pivot_output_is_sanitized():
    # #7: a hostile pivot page with an ESC + bidi char must be escaped in the
    # recorded detail/flag.
    page = "hi\x1b[2Jevil‮ FLAG{s\x1bx}"
    t = make_cmdi_engine_transport({"http://10.0.0.9:8100/": page})
    scope = EngagementScope(hosts=["10.0.0.1", "10.0.0.9"],
                            urls=["http://10.0.0.1:80/", "http://10.0.0.9:8100/"],
                            allow_post_exploit=True, allow_lateral=True, max_hosts=4)
    r = RedTeamEngine(scope, transport=t).attempt("cmdi", "http://10.0.0.1:80/a", "p")
    detail = r.lateral["pivots"][0]["detail"] + r.lateral["pivots"][0]["flag"]
    assert "\x1b" not in detail and "‮" not in detail
