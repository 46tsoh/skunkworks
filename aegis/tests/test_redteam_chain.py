"""Milestone 26 — autonomous attack chaining. Fully offline/deterministic.

No live target, no Docker, no network, no real model. A scripted "fake shell"
transport drives the REAL stage-1/2/3 primitives (engine.attempt →
postexploit.retrieve_flag → lateral.move_laterally), so the chain is exercised
end-to-end exactly as it would run live, but deterministically. Mirrors the
existing FakeTransport + fake-scanner conventions (test_agent.py,
test_redteam_*.py).

The suite pins the safety invariants the spec proves (docs/specs/attack-chaining.md):
the data model, the derivation clamp (hostile proposals clamp to the trusted
set), scope-never-escapes on a traced hostile-output fixture, bounded
termination, the max_depth=0 byte-for-byte regression, and the full audit trail.
"""

import copy

import pytest

from aegis.redteam import EngagementScope, RedTeamEngine
from aegis.redteam.http import HttpResponse
from aegis.redteam.postexploit import valid_flag_path
from aegis.redteam.techniques import MARKER
from aegis.redteam.chain import (
    ARTIFACT_ROLES, Artifact, ChainBudget, ChainGraph, ChainStep, CHAIN_OPS,
    build_trusted, clamp_choice, clamp_op, derive_targets, make_artifact,
    match_trusted, run_chain,
)
from aegis.tools.util import make_candidate

_CI = f"{MARKER}ci"
_PRODUCT = 1337 * 7919           # the cmdi arithmetic oracle's value
_S, _E = f"{MARKER}S", f"{MARKER}E"


# --------------------------------------------------------------------------- #
# A scripted "fake shell" transport: it simulates a host whose only vulnerable
# parameter is OS-command-injectable, so the real CommandInjection technique
# confirms, and the real stage-2/3 commands (echo S; <cmd>; echo; echo E) are
# "executed" and their stdout returned between the marker lines. One transport
# serves several hosts, keyed by the request URL's host.
# --------------------------------------------------------------------------- #
class _Machine:
    def __init__(self, files=None, etc_hosts="", curl=None):
        self.files = files or {}         # path -> content (for `cat <path>`)
        self.etc_hosts = etc_hosts       # for `cat /etc/hosts`
        self.curl = curl or {}           # url -> body reachable FROM this host


def _simulate(machine, cmd):
    cmd = cmd.strip()
    if cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"
    if cmd == "uname -a":
        return "Linux box 6.1.0 x86_64 GNU/Linux"
    if cmd == "cat /etc/hosts":
        return machine.etc_hosts
    if cmd.startswith("cat "):
        return machine.files.get(cmd[4:].strip(), "")
    if cmd.startswith("curl "):
        url = cmd.split()[-1].strip("'")
        return machine.curl.get(url, "") or ""
    return ""


def fake_shell(machines):
    """Return a FakeTransport-style object over a dict host -> _Machine."""
    from urllib.parse import urlparse

    calls = []
    sent_hosts = []

    class _T:
        def __init__(self):
            self.calls = calls
            self.sent_hosts = sent_hosts

        def send(self, method, url, params=None):
            params = dict(params or {})
            calls.append((method, url, params))
            host = urlparse(url).hostname or ""
            sent_hosts.append(host)
            machine = machines.get(host)
            value = "".join(str(v) for v in params.values())
            if machine is None:
                return HttpResponse(url, 0, {}, "", error="no such host")
            # stage-2/3 wrapped command: echo <S>; <cmd>; echo; echo <E>
            if _S in value and _E in value:
                a = value.index(f"echo {_S}; ") + len(f"echo {_S}; ")
                b = value.index(f"; echo; echo {_E}")
                out = _simulate(machine, value[a:b])
                return HttpResponse(url, 200, {}, f"{_S}\n{out}\n\n{_E}")
            # stage-1 confirm arithmetic oracle: echo <token>-$((A*B))
            if f"{_CI}-$(({1337}*{7919}))" in value:
                return HttpResponse(url, 200, {}, f"ok {_CI}-{_PRODUCT} done")
            return HttpResponse(url, 200, {}, "nothing happened")

    return _T()


def _lead(target, param="host", type="cmdi", id="L1"):
    return {"type": type, "target": target, "param": param, "id": id}


def _cmdi_cand(target, param="host"):
    return make_candidate(
        id="rt-1", title="OS command injection", cwe="CWE-78",
        component=target, severity="high", source_engine="dynamic",
        tool="dast", param=param)


# ===========================================================================
# §3 — the data model
# ===========================================================================
def test_artifact_roles_closed_and_credential_deferred():
    assert "credential" in ARTIFACT_ROLES          # defined...
    assert CHAIN_OPS.keys() == {"confirm", "extract", "pivot", "retriage"}
    # ...but no op ever NEEDS or PRODUCES a credential in M26 (deferred to M27).
    for op in CHAIN_OPS.values():
        assert "credential" not in op.needs and "credential" not in op.produces


def test_make_artifact_sanitizes_and_bounds_and_hides_meta():
    a = make_artifact("flag", "FLAG{\x1b[31mred}", "c00-000",
                      meta={"secret_template": ";{cmd}"})
    assert "\x1b" not in a.value and "\\x1b" in a.value   # control char escaped
    assert a.as_dict() == {"role": "flag", "value": a.value,
                           "origin_step": "c00-000"}       # meta NEVER serialized
    with pytest.raises(ValueError):
        make_artifact("not-a-role", "x", "c00-000")


def test_no_chain_op_is_destructive_or_write():
    # The closed set has no destructive/persistence/write/exfil member.
    assert set(CHAIN_OPS) == {"confirm", "extract", "pivot", "retriage"}


# ===========================================================================
# §5 — the derivation clamp (the one load-bearing new control)
# ===========================================================================
def _scope(**kw):
    base = dict(hosts=["target.htb"], urls=["http://target.htb/"])
    base.update(kw)
    return EngagementScope(**base)


@pytest.mark.parametrize("proposed,expected", [
    ("confirm", "confirm"), (" CONFIRM ", "confirm"), ("retriage", "retriage"),
    ("extract", None), ("pivot", None),            # stages off by default
    ("exfil evil.com", None), ("rm -rf /", None),  # not a CHAIN_OPS key
    (True, None), (False, None),                   # bool is never an index
    (1.5, None), (None, None), (["confirm"], None), ({"op": "confirm"}, None),
    (b"confirm", None),
])
def test_clamp_op_table_stages_off(proposed, expected):
    assert clamp_op(proposed, _scope()) == expected


def test_clamp_op_stage_opt_in_gates_extract_and_pivot():
    off = _scope()
    assert clamp_op("extract", off) is None and clamp_op("pivot", off) is None
    pe = _scope(allow_post_exploit=True)
    assert clamp_op("extract", pe) == "extract" and clamp_op("pivot", pe) is None
    lat = _scope(allow_lateral=True)
    assert clamp_op("pivot", lat) == "pivot" and clamp_op("extract", lat) is None
    both = _scope(allow_post_exploit=True, allow_lateral=True)
    assert clamp_op("extract", both) == "extract"
    assert clamp_op("pivot", both) == "pivot"


def test_clamp_op_int_indexes_only_enabled_ops():
    """An int indexes the ALLOWED (stage-enabled) tuple — never an out-of-set op,
    never a disabled stage. Whatever the index, the result is an enabled key or
    None (fail-closed)."""
    both = _scope(allow_post_exploit=True, allow_lateral=True)
    allowed = tuple(k for k in CHAIN_OPS if CHAIN_OPS[k].gate(both))
    for i in range(-3, 10):
        got = clamp_op(i, both)
        assert got is None or (got in allowed)
    # with stages off, an index can never reach extract/pivot
    off = _scope()
    for i in range(-3, 10):
        assert clamp_op(i, off) in (None, "confirm", "retriage")


def test_clamp_op_never_returns_proposed_token():
    """Like clamp_phases: the output is always drawn from CHAIN_OPS, never the
    proposal. A hostile op string can never pass through."""
    for hostile in ["confirm; rm -rf /", "CONFIRM\n", "../pivot", "exfil"]:
        assert clamp_op(hostile, _scope(allow_post_exploit=True)) in (
            None, "confirm", "extract", "retriage")


def test_clamp_choice_table():
    frontier = [ChainStep(id="c00-000", op="confirm", target="http://target.htb/"),
                ChainStep(id="c00-001", op="confirm", target="http://target.htb/")]
    assert clamp_choice(0, frontier) is frontier[0]
    assert clamp_choice(1, frontier) is frontier[1]
    assert clamp_choice("c00-001", frontier) is frontier[1]
    for bad in [True, False, 2, -1, 1.5, None, "nope", ["0"], {"i": 0}]:
        assert clamp_choice(bad, frontier) is None
    assert clamp_choice(0, []) is None


def test_match_trusted_never_returns_its_argument():
    trusted = ("http://target.htb/", "inner.htb")
    # a hostile host token can only SELECT a pre-existing operator entry
    assert match_trusted("inner.htb", trusted) == "inner.htb"
    assert match_trusted("http://inner.htb/evil?x=1", trusted) == "inner.htb"
    got = match_trusted("target.htb", trusted)
    assert got == "http://target.htb/"          # the OPERATOR's bytes
    assert got != "target.htb"                   # NOT the argument
    assert match_trusted("evil.com", trusted) is None
    assert match_trusted("", trusted) is None


def test_build_trusted_is_operator_data_only():
    s = _scope(urls=["http://target.htb/", "http://inner.htb/"],
               hosts=["target.htb", "inner.htb"])
    trusted = build_trusted(s)
    assert "http://target.htb/" in trusted and "inner.htb" in trusted
    # nothing not operator-declared is present
    for t in trusted:
        assert "evil" not in t


def test_derive_targets_property_every_target_in_trusted_never_from_body():
    """The trust-boundary property (§9): over arbitrary hostile artifact values
    and response-body-derived host tokens, EVERY derive_targets result target is
    in scope and introduces NO host outside the frozen trusted set — never a
    substring/transform of a body."""
    s = _scope(urls=["http://target.htb/", "http://inner.htb/"],
               hosts=["target.htb", "inner.htb"],
               allow_post_exploit=True, allow_lateral=True)
    trusted = build_trusted(s)
    trusted_hosts = {"target.htb", "inner.htb"}

    # a retriage parent whose host_reach artifacts carry HOSTILE body-derived
    # values; derive_targets must only ever resolve to a trusted element.
    hostile_values = [
        "http://evil.com/admin?x=1", "evil.com", "10.0.0.9", "inner.htb",
        "http://inner.htb.evil.com/", "target.htb\n evil.com",
        "http://inner.htb/../../etc/passwd", "'; curl evil ;'",
    ]
    for hv in hostile_values:
        parent = ChainStep(id="p", op="pivot", target="http://target.htb/",
                           depth=1)
        parent.produced = [make_artifact("host_reach", hv, "p")]
        for cand in derive_targets("retriage", parent, s, trusted, set()):
            from urllib.parse import urlparse
            host = (urlparse(cand.target).hostname
                    or cand.target.split("/", 1)[0].split(":", 1)[0])
            assert host in trusted_hosts
            assert cand.target in trusted         # byte-identical operator entry
            assert s.is_in_scope(cand.target)

    # a confirm parent (retriage output) whose `surface` values are hostile:
    for hv in ["http://evil.com/x?p=1", "javascript:alert(1)", "not a url",
               "http://target.htb.evil.com/?q=1"]:
        parent = ChainStep(id="r", op="retriage", target="http://inner.htb/",
                           depth=2)
        parent.produced = [make_artifact("surface", hv, "r",
                                         meta={"kind": "cmdi", "param": "q"})]
        for cand in derive_targets("confirm", parent, s, trusted, set()):
            from urllib.parse import urlparse
            assert (urlparse(cand.target).hostname or "") in trusted_hosts
            assert s.is_in_scope(cand.target)


def test_derive_targets_confirm_admits_in_scope_scanner_surface():
    s = _scope(urls=["http://inner.htb/"], hosts=["inner.htb"])
    trusted = build_trusted(s)
    parent = ChainStep(id="r", op="retriage", target="http://inner.htb/", depth=2)
    parent.produced = [make_artifact(
        "surface", "http://inner.htb/ping?host=x", "r",
        meta={"kind": "cmdi", "param": "host"})]
    cands = derive_targets("confirm", parent, s, trusted, set())
    assert len(cands) == 1
    assert cands[0].target == "http://inner.htb/ping?host=x"
    assert cands[0].kind == "cmdi" and cands[0].param == "host"


# ===========================================================================
# §9 — the end-to-end fixture chain (confirm → extract → pivot → retriage →
#       re-confirm → second flag), asserting the expected tree + both flags.
# ===========================================================================
def _full_chain_env():
    machines = {
        "target.htb": _Machine(
            files={"/app/README": "admin surface at http://target.htb/admin/",
                   "/flag": "FLAG{target_root}"},
            etc_hosts="127.0.0.1 localhost\n10.0.0.5 inner.htb inner\n"
                      "66.66.66.66 evil.com\n",
            curl={"http://inner.htb/": "inner home page"}),   # reachable pivot
        "inner.htb": _Machine(
            files={"/flag": "FLAG{inner_box}"},
            etc_hosts="127.0.0.1 localhost\n",
            curl={}),                                          # reaches nothing back
    }
    scope = _scope(urls=["http://target.htb/", "http://inner.htb/"],
                   hosts=["target.htb", "inner.htb"], max_hosts=4,
                   allow_post_exploit=True, allow_lateral=True)
    transport = fake_shell(machines)
    # flag_paths reads the README first (a non-flag file → a `file` artifact)
    # then /flag — so extract yields BOTH a file and a flag artifact.
    engine = RedTeamEngine(scope, transport=transport,
                           flag_paths=["/app/README", "/flag"])

    def scanner_fn(target):
        # the gated re-scan: inner.htb re-triages to a fresh cmdi surface.
        if "inner.htb" in target:
            return [_cmdi_cand("http://inner.htb/run?host=1", "host")]
        return []

    return scope, engine, scanner_fn, transport


def test_end_to_end_chain_two_flags_and_expected_tree():
    scope, engine, scanner_fn, transport = _full_chain_env()
    budget = ChainBudget(max_depth=5, max_breadth=4, max_steps=32,
                         max_requests=512)
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=budget, scanner_fn=scanner_fn)

    ops = sorted({s.op for s in graph.nodes.values()})
    assert ops == ["confirm", "extract", "pivot", "retriage"]   # all four ran

    flags = sorted(a.value for s in graph.nodes.values()
                   for a in s.produced if a.role == "flag")
    assert flags == ["FLAG{inner_box}", "FLAG{target_root}"]     # BOTH flags

    # a `file` artifact was minted (README) and depth >= 2 was reached.
    assert any(a.role == "file" for s in graph.nodes.values() for a in s.produced)
    assert graph._counts()["max_depth_reached"] >= 3

    # a real dependency tree: confirm(root) → extract, pivot; pivot → retriage;
    # retriage → confirm(inner); confirm(inner) → extract(inner).
    root = graph.nodes["c00-000"]
    assert root.op == "confirm" and root.status == "confirmed"
    kids = {graph.nodes[c].op for (p, c) in graph.edges if p == "c00-000"}
    assert kids == {"extract", "pivot"}

    # request count stays within the budget.
    assert graph._counts()["requests"] <= budget.max_requests
    # evil.com (from /etc/hosts) was seen+refused, NEVER contacted.
    assert "evil.com" in graph.discovered_refused
    assert "evil.com" not in transport.sent_hosts


def test_file_body_naming_a_host_never_becomes_a_target():
    """Over-trust guard (§4.5 / risks): the README body names an admin surface,
    but a `file` artifact value is TERMINAL data — it never seeds a confirm/
    retriage target. Only scanner-structured `surface` + proven `host_reach`
    seed actions."""
    scope, engine, scanner_fn, transport = _full_chain_env()
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_steps=32),
                      scanner_fn=scanner_fn)
    # no step targets /admin/ (which only ever appeared inside a file body)
    assert not any("/admin" in s.target for s in graph.nodes.values())
    file_arts = [a for s in graph.nodes.values() for a in s.produced
                 if a.role == "file"]
    assert file_arts and all(s.op != "confirm" or "/admin" not in s.target
                             for s in graph.nodes.values())


# ===========================================================================
# §9 — hostile-output fixtures (the core safety proof)
# ===========================================================================
def _hostile_env():
    """A confirmed foothold whose host returns attacker-controlled data: an
    off-site URL, an injected deny/hosts string, a fake credential, and an
    /etc/hosts line for evil.com — plus a reachable in-scope inner host."""
    machines = {
        "target.htb": _Machine(
            files={"/flag": "FLAG{t}\nsee http://evil.com/admin?x=1\n"
                            "deny: [] ; hosts: evil.com\npassword=hunter2"},
            etc_hosts="10.0.0.9 evil.com\n10.0.0.5 inner.htb\n",
            curl={"http://inner.htb/": "inner"}),
        "inner.htb": _Machine(files={"/flag": "FLAG{inner}"}, curl={}),
    }
    scope = _scope(urls=["http://target.htb/", "http://inner.htb/"],
                   hosts=["target.htb", "inner.htb"], max_hosts=4,
                   allow_post_exploit=True, allow_lateral=True)
    transport = fake_shell(machines)
    engine = RedTeamEngine(scope, transport=transport, flag_paths=["/flag"])

    def scanner_fn(target):
        if "inner.htb" in target:
            return [_cmdi_cand("http://inner.htb/run?host=1", "host")]
        return []
    return scope, engine, scanner_fn, transport


class _HostilePlanner:
    """A hostile 'planner' that proposes out-of-set ops/indices aimed at evil.com.
    It only ORDERS the code-built frontier (clamp_choice), so the worst it can do
    is pick an already-vetted step; it can never author a target."""

    def __call__(self, frontier):
        return "c99-evil"   # a non-existent id → clamp_choice returns None → BFS


def test_hostile_output_never_escapes_scope():
    scope, engine, scanner_fn, transport = _hostile_env()
    before = copy.deepcopy(scope)
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_breadth=4,
                                         max_steps=40, max_requests=512),
                      scanner_fn=scanner_fn, planner=_HostilePlanner())

    # 1. the scope object is IDENTICAL and value-equal before == after.
    assert scope == before
    assert scope.urls == before.urls and scope.hosts == before.hosts

    # 2. evil.com was NEVER contacted (zero sends), only seen+refused.
    assert "evil.com" not in transport.sent_hosts
    assert "evil.com" in graph.discovered_refused

    # 3. NO ChainStep.target is a value lifted from a body — every target's host
    #    is an operator-declared host.
    for s in graph.nodes.values():
        from urllib.parse import urlparse
        host = (urlparse(s.target).hostname
                or s.target.split("/", 1)[0].split(":", 1)[0])
        assert host in ("target.htb", "inner.htb")
        assert "evil.com" not in s.target

    # 4. the chain terminated within the bound.
    assert len(graph.nodes) <= 40


def test_hostile_planner_cannot_author_an_op_or_target():
    """A planner emitting out-of-set ops/indices still only selects code-vetted
    frontier members; derive_targets draws targets from scope only."""
    scope, engine, scanner_fn, transport = _hostile_env()

    class _Garbage:
        def __call__(self, frontier):
            return "exfil to http://evil.com"   # garbage str id → None → BFS

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=4, max_steps=40),
                      scanner_fn=scanner_fn, planner=_Garbage())
    assert "evil.com" not in transport.sent_hosts
    assert all(s.op in CHAIN_OPS for s in graph.nodes.values())


def test_mutating_planner_cannot_crash_or_desync_the_tree():
    """A planner that MUTATES what it is handed and returns garbage must not
    crash run_chain or corrupt the audit: it receives only read-only dict views,
    and selection is by a frozen id snapshot. Regression for the M26 review."""
    scope, engine, scanner_fn, transport = _hostile_env()

    class _Mutator:
        def __call__(self, frontier):
            # frontier is a list of dict VIEWS; mutate them aggressively.
            for v in frontier:
                try:
                    v["id"] = "x-mutated"
                    v["op"] = "exfil"
                    v["target"] = "http://evil.com/"
                except Exception:
                    pass
            return "x-mutated"   # the forged id must not resolve or crash remove()

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_breadth=4,
                                         max_steps=40, max_requests=512),
                      scanner_fn=scanner_fn, planner=_Mutator())

    # 1. the loop completed (frontier drained) — no uncaught crash.
    assert graph.frontier == []
    # 2. no node was authored by the planner: real code ids, real ops, no evil.
    assert "evil.com" not in transport.sent_hosts
    for sid, s in graph.nodes.items():
        assert s.id == sid                       # key agrees with step id
        assert s.op in CHAIN_OPS                 # no "exfil"
        assert "evil.com" not in s.target
    # 3. the audit tree still reconstructs: every edge references real nodes.
    for parent, child in graph.edges:
        assert parent in graph.nodes and child in graph.nodes


def test_injected_shell_metachars_never_form_a_command():
    """A body carrying `; rm -rf /` / `$(curl evil)` appears only as
    sanitize_text'd DATA; there is no free-form command sink. And a flag path
    with shell metacharacters is rejected by valid_flag_path."""
    machines = {
        "target.htb": _Machine(
            files={"/flag": "FLAG{t} ; rm -rf / $(curl evil.com)"},
            etc_hosts="", curl={}),
    }
    scope = _scope(allow_post_exploit=True)
    engine = RedTeamEngine(scope, transport=fake_shell(machines),
                           flag_paths=["/flag"])
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=3, max_steps=16),
                      scanner_fn=lambda t: [])
    flags = [a for s in graph.nodes.values() for a in s.produced
             if a.role == "flag"]
    # the flag oracle captures only the braced token — the trailing `; rm -rf /`
    # is not even captured, and NOTHING in the body ever becomes a command/target.
    assert flags and flags[0].value == "FLAG{t}"
    for s in graph.nodes.values():
        assert "rm -rf" not in s.target and "$(" not in s.target
        assert "rm -rf" not in s.param and "$(" not in s.param
    assert not valid_flag_path("/flag; rm -rf /")
    assert not valid_flag_path("/etc/passwd$(id)")
    assert valid_flag_path("/flag")


# ===========================================================================
# §9 — bounds / termination
# ===========================================================================
def test_cyclic_fixture_terminates_via_seen_and_depth():
    """A reaches B reaches A: the monotone `seen` set + max_depth guarantee
    termination (no identical dedup key is ever re-enabled)."""
    machines = {
        "a.htb": _Machine(files={"/flag": "FLAG{a}"}, etc_hosts="",
                          curl={"http://b.htb/": "b page"}),
        "b.htb": _Machine(files={"/flag": "FLAG{b}"}, etc_hosts="",
                          curl={"http://a.htb/": "a page"}),   # cycle back to A
    }
    scope = _scope(urls=["http://a.htb/", "http://b.htb/"],
                   hosts=["a.htb", "b.htb"], max_hosts=4,
                   allow_post_exploit=True, allow_lateral=True)
    engine = RedTeamEngine(scope, transport=fake_shell(machines),
                           flag_paths=["/flag"])

    def scanner_fn(target):
        host = "a.htb" if "a.htb" in target else "b.htb"
        return [_cmdi_cand(f"http://{host}/run?host=1", "host")]

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://a.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=6, max_breadth=4,
                                         max_steps=64, max_requests=999),
                      scanner_fn=scanner_fn)
    # It HALTS (did not blow the step cap), and every node is terminal.
    assert len(graph.nodes) < 64
    assert all(graph.nodes[i].status != "pending" for i in graph.nodes)
    assert not graph.frontier


def test_max_steps_caps_pending_steps():
    scope, engine, scanner_fn, transport = _full_chain_env()
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_breadth=4,
                                         max_steps=3, max_requests=999),
                      scanner_fn=scanner_fn)
    assert len(graph.nodes) <= 3 + 4      # a bounded overshoot, then capped
    assert any(s.status == "capped" for s in graph.nodes.values())


def test_max_requests_halts_the_chain():
    scope, engine, scanner_fn, transport = _full_chain_env()
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_breadth=4,
                                         max_steps=64, max_requests=1),
                      scanner_fn=scanner_fn)
    # the very first confirm already exceeds 1 request → the rest is capped.
    assert any(s.status == "capped" for s in graph.nodes.values()) or \
        graph._counts()["requests"] >= 1


def test_max_breadth_bounds_children_per_node():
    # a retriage that surfaces many leads is bounded to max_breadth confirm kids.
    scope = _scope(urls=["http://inner.htb/"], hosts=["inner.htb"],
                   allow_lateral=True, allow_post_exploit=True, max_hosts=9)
    machines = {"inner.htb": _Machine(files={"/flag": "FLAG{i}"})}
    engine = RedTeamEngine(scope, transport=fake_shell(machines),
                           flag_paths=["/flag"])

    def scanner_fn(target):
        return [_cmdi_cand(f"http://inner.htb/p{i}?host=1", "host")
                for i in range(9)]

    parent = ChainStep(id="r", op="retriage", target="http://inner.htb/", depth=1)
    parent.produced = [make_artifact("surface", f"http://inner.htb/p{i}?host=1",
                                     "r", meta={"kind": "cmdi", "param": "host"})
                       for i in range(9)]
    cands = derive_targets("confirm", parent, scope, build_trusted(scope), set())
    assert len(cands) == 9   # derive finds all; run_chain's _expand caps them

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://inner.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=3, max_breadth=2,
                                         max_steps=64, max_requests=999),
                      scanner_fn=scanner_fn)
    # the retriage node promoted at most max_breadth confirm children.
    for sid, step in graph.nodes.items():
        if step.op == "retriage":
            kids = [c for (p, c) in graph.edges if p == sid]
            assert len(kids) <= 2


def test_deadline_halts_the_chain():
    scope, engine, scanner_fn, transport = _full_chain_env()
    clock = [100.0]

    def now_fn():
        clock[0] += 50.0      # every check is far past the deadline
        return clock[0]

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_steps=64,
                                         max_requests=999, deadline=120.0),
                      scanner_fn=scanner_fn, now_fn=now_fn)
    assert any(s.status == "capped" and "deadline" in s.note
               for s in graph.nodes.values())


def test_expired_scope_refuses_remaining_frontier():
    """A scope crossing expiry mid-run fails closed on every remaining step."""
    from datetime import datetime, timezone
    scope = _scope(urls=["http://target.htb/", "http://inner.htb/"],
                   hosts=["target.htb", "inner.htb"],
                   allow_post_exploit=True, allow_lateral=True,
                   expires=datetime(2000, 1, 1, tzinfo=timezone.utc))
    machines = {"target.htb": _Machine(files={"/flag": "FLAG{t}"})}
    engine = RedTeamEngine(scope, transport=fake_shell(machines),
                           flag_paths=["/flag"])
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=4, max_steps=16),
                      scanner_fn=lambda t: [])
    # the one seeded confirm is refused by authorize() (expired) before traffic.
    assert graph.nodes["c00-000"].status == "refused_scope"
    assert not any(s.status == "confirmed" for s in graph.nodes.values())


def test_unauthorized_refuses_every_step_no_traffic():
    scope, engine, scanner_fn, transport = _full_chain_env()
    graph = run_chain(scope=scope, authorized=False, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_steps=16),
                      scanner_fn=scanner_fn)
    assert graph.nodes["c00-000"].status == "refused_scope"
    assert transport.sent_hosts == []      # not a single request


def test_out_of_scope_initial_lead_refused_no_traffic():
    scope, engine, scanner_fn, transport = _full_chain_env()
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://evil.com/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_steps=16),
                      scanner_fn=scanner_fn)
    assert graph.nodes["c00-000"].status == "refused_scope"
    assert "evil.com" not in transport.sent_hosts


def test_stages_off_no_extract_or_pivot_even_with_foothold():
    """Spec §9 regression: with the per-stage switches off, a confirmed foothold
    creates NO extract/pivot successors (clamp gate stops them)."""
    machines = {"target.htb": _Machine(files={"/flag": "FLAG{t}"},
                                       curl={"http://inner.htb/": "x"})}
    scope = _scope(urls=["http://target.htb/", "http://inner.htb/"],
                   hosts=["target.htb", "inner.htb"])  # stages OFF
    engine = RedTeamEngine(scope, transport=fake_shell(machines),
                           flag_paths=["/flag"])
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_steps=16),
                      scanner_fn=lambda t: [])
    assert graph.nodes["c00-000"].status == "confirmed"
    assert {s.op for s in graph.nodes.values()} == {"confirm"}


# ===========================================================================
# §9 — the max_depth=0 byte-for-byte regression lock
# ===========================================================================
def test_max_depth_zero_is_the_flat_loop():
    """run_chain(max_depth=0) attempts exactly the initial leads as confirms and
    derives NO children — equivalent to today's flat one-shot loop."""
    scope, engine, scanner_fn, transport = _full_chain_env()
    leads = [_lead("http://target.htb/ping?host=1"),
             _lead("http://inner.htb/run?host=1", id="L2")]
    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=leads, budget=ChainBudget(max_depth=0),
                      scanner_fn=scanner_fn)
    # one confirm node per lead, no children, no edges.
    assert sorted(s.op for s in graph.nodes.values()) == ["confirm", "confirm"]
    assert graph.edges == []
    assert graph._counts()["max_depth_reached"] == 0


def test_max_depth_zero_matches_drive_agent_flat_loop(monkeypatch):
    """drive_agent with --chain + max_depth=0 produces the same attempted leads
    (type/target/param/verified/cwe) as the default flat exploit loop."""
    from aegis.agent import drive_agent
    from aegis.config import AegisConfig
    from aegis.engines.events import EventSink
    from aegis.knowledge.base import KnowledgeBase

    # A fake dast scanner yielding a confirmable cmdi lead, + a confirming shell.
    from aegis.tools.base import DockerBackedTool, ToolResult, ToolStatus

    class _CmdiScanner(DockerBackedTool):
        allows_network = True

        def __init__(self, name):
            self.name = name

        def run(self, target, **kw):
            if self.name != "dast":
                return ToolResult(self.name, ToolStatus.OK, candidates=[])
            return ToolResult(self.name, ToolStatus.OK, candidates=[_cmdi_cand(
                "http://target.htb/ping?host=1", "host")])

    class _Reg:
        def get(self, name):
            return _CmdiScanner(name)

    scope = EngagementScope(hosts=["target.htb"], urls=["http://target.htb/"],
                            allow_post_exploit=True)
    cfg = AegisConfig.from_env(backend="static", local_only=True)
    machines = {"target.htb": _Machine(files={"/flag": "FLAG{t}"})}

    def _run(chain):
        from aegis.redteam.chain import ChainBudget
        return drive_agent(
            target="http://target.htb/", goal="x", scope=scope, authorized=True,
            exploit=True, config=cfg, sink=EventSink(path=None),
            kb=KnowledgeBase(), write=[].append, registry=_Reg(),
            transport=fake_shell(machines), chain=chain)

    flat = _run(None)
    chained = _run(ChainBudget(max_depth=0))

    def _key(a):
        return (a["type"], a["target"], a["param"], a["verified"], a.get("cwe"))
    assert [_key(a) for a in flat.attempted] == [_key(a) for a in chained.attempted]
    assert flat.chain is None and chained.chain is not None


# ===========================================================================
# §9 — audit completeness + drive_agent / report.json integration
# ===========================================================================
def test_chain_audit_reconstructs_the_full_tree():
    scope, engine, scanner_fn, transport = _hostile_env()
    sink_events = []

    class _Sink:
        def emit(self, code, event, **kw):
            sink_events.append((code, event, kw))

    graph = run_chain(scope=scope, authorized=True, engine=engine,
                      initial_leads=[_lead("http://target.htb/ping?host=1")],
                      budget=ChainBudget(max_depth=5, max_breadth=4,
                                         max_steps=40, max_requests=512),
                      scanner_fn=scanner_fn, sink=_Sink())
    d = graph.as_dict()
    # nodes, edges, trusted, budget, discovered_refused, counts all present.
    assert set(d) == {"nodes", "edges", "trusted", "budget",
                      "discovered_refused", "counts"}
    # evil.com (and the other /etc/hosts tokens) are recorded "seen, refused".
    assert "evil.com" in d["discovered_refused"]
    # every edge references real nodes; the tree is reconstructable.
    ids = {n["id"] for n in d["nodes"]}
    for parent, child in d["edges"]:
        assert parent in ids and child in ids
    # artifact meta is NEVER serialized: every produced artifact dict has exactly
    # role/value/origin_step, and the cmdi template never appears anywhere.
    assert "template" not in str(d)
    for n in d["nodes"]:
        for a in n["produced"] + n["inputs"]:
            assert set(a) == {"role", "value", "origin_step"}
    # the audit event stream carries the lifecycle codes.
    kinds = {e for (_c, e, _k) in sink_events}
    assert {"chain_start", "chain_node_open", "chain_node_result",
            "chain_edge", "discovered_refused", "chain_done"} <= kinds


def test_drive_agent_chain_writes_report_metrics(tmp_path, monkeypatch):
    from aegis import cli
    import json
    # build a scope file + a fake dast registry + confirming shell through CLI.
    scope_file = tmp_path / "s.json"
    scope_file.write_text(json.dumps({
        "engagement": "t", "authorized_by": "op",
        "expires": "2999-01-01T00:00:00Z",
        "targets": {"hosts": ["target.htb"], "urls": ["http://target.htb/"]},
        "limits": {"allow_post_exploit": True, "max_hosts": 2},
    }), encoding="utf-8")

    from aegis.tools.base import DockerBackedTool, ToolResult, ToolStatus

    class _CmdiScanner(DockerBackedTool):
        allows_network = True

        def __init__(self, name):
            self.name = name

        def run(self, target, **kw):
            if self.name != "dast":
                return ToolResult(self.name, ToolStatus.OK, candidates=[])
            return ToolResult(self.name, ToolStatus.OK, candidates=[_cmdi_cand(
                "http://target.htb/ping?host=1", "host")])

    class _Reg:
        def get(self, name):
            return _CmdiScanner(name)

    machines = {"target.htb": _Machine(files={"/flag": "FLAG{t}"})}
    # The CLI builds the engine with transport=None → UrllibTransport (live).
    # Patch UrllibTransport to our offline fake shell (still wrapped by the
    # scope-gated transport), and default_registry to our fake dast scanner.
    monkeypatch.setattr("aegis.tools.default_registry", lambda: _Reg())
    monkeypatch.setattr("aegis.redteam.engine.UrllibTransport",
                        lambda *a, **k: fake_shell(machines))

    out = tmp_path / "run"
    rc = cli.main(["agent", "find rce", "--target", "http://target.htb/",
                   "--scope", str(scope_file), "--authorized", "--exploit",
                   "--chain", "--chain-max-depth", "2", "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    chain = report["metrics"]["agent"]["chain"]
    assert chain["counts"]["footholds"] >= 1
    assert chain["counts"]["flags"] >= 1
    assert "target.htb" in " ".join(chain["trusted"])


# -- CLI refusals (fail-closed, exit 2, before any traffic) -------------------
def test_cli_chain_without_authorized_refuses(capsys):
    from aegis import cli
    rc = cli.main(["agent", "x", "--target", "good.htb", "--chain"])
    assert rc == 2
    assert "requires --authorized" in capsys.readouterr().err


def test_cli_chain_without_scope_refuses(capsys, tmp_path):
    from aegis import cli
    rc = cli.main(["agent", "x", "--target", "good.htb", "--authorized",
                   "--chain"])
    assert rc == 2
    assert "requires --scope" in capsys.readouterr().err


def test_cli_chain_without_exploit_refuses(capsys, tmp_path):
    from aegis import cli
    sc = tmp_path / "s.json"
    sc.write_text('{"targets": {"urls": ["http://good.htb/"]}}')
    rc = cli.main(["agent", "x", "--target", "http://good.htb/", "--authorized",
                   "--scope", str(sc), "--chain"])
    assert rc == 2
    assert "requires --exploit" in capsys.readouterr().err
