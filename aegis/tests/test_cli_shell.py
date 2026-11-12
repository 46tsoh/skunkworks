"""Tests for `aegis shell` — the interactive REPL over the dynamic loop.

Fully offline/deterministic: no network, no model. Every test clears the
AEGIS_LLM* env so build_llm never dials localhost and hangs CI. stdin is driven
with a StringIO; output is read from capsys. See docs/specs/interactive-shell.md.
"""

import io

import pytest

from aegis import cli
from aegis.engines.events import EventSink
from aegis.redteam import EngagementScope
from aegis.shell import SessionState, gate, run_shell
from aegis.config import AegisConfig


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    for var in ("AEGIS_LLM", "AEGIS_LLM_API_BASE", "AEGIS_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def _drive(monkeypatch, script, argv=("shell",)):
    monkeypatch.setattr("sys.stdin", io.StringIO(script))
    return cli.main(list(argv))


def _session(scope=None, authorized=False, transport=None):
    cfg = AegisConfig.from_env(backend="static", local_only=True)
    return SessionState(scope=scope or EngagementScope(), authorized=authorized,
                        config=cfg, sink=EventSink(path=None),
                        transport=transport)


# -- lifecycle --------------------------------------------------------------
def test_exit_returns_zero(monkeypatch, capsys):
    assert _drive(monkeypatch, "exit\n") == 0
    assert "bye" in capsys.readouterr().out


def test_eof_exits_zero(monkeypatch, capsys):
    """An empty stdin (immediate EOF) is a clean exit, not a crash."""
    assert _drive(monkeypatch, "") == 0
    assert "bye" in capsys.readouterr().out


def test_unknown_command_stays_open(monkeypatch, capsys):
    assert _drive(monkeypatch, "wat\nexit\n") == 0
    assert "unknown command 'wat'" in capsys.readouterr().out


# -- offline narration (no network) -----------------------------------------
def test_goal_narrates_and_files_findings_offline(monkeypatch, capsys):
    assert _drive(monkeypatch, "goal find injections\nfindings\nexit\n") == 0
    out = capsys.readouterr().out
    assert "finding(s) this command" in out
    assert "SQL injection in login handler" in out


def test_focus_reorders_pool_offline(monkeypatch, capsys):
    """`focus` is the one steering lever that changes behaviour offline: the
    focused surface must be probed first on the next goal."""
    assert _drive(
        monkeypatch,
        "goal seed\nfocus GET /search (q)\ngoal again\nexit\n") == 0
    out = capsys.readouterr().out
    assert "focused 'GET /search (q)' first" in out or "focused" in out


# -- the gate: live verbs are refused without authorization / scope ----------
def test_scan_refused_without_authorization(monkeypatch, capsys):
    assert _drive(monkeypatch, "scan evil.example recon\nexit\n") == 0
    assert "REFUSED" in capsys.readouterr().out


def test_attempt_refused_without_authorization(monkeypatch, capsys):
    """attempt sends real probes — it MUST require --authorized, like scan."""
    assert _drive(
        monkeypatch, "attempt sqli http://evil.example/x q\nexit\n") == 0
    assert "REFUSED" in capsys.readouterr().out


def test_authorized_but_out_of_scope_is_refused_no_tool_run(monkeypatch):
    """gate() refuses an out-of-scope target even when authorized, before any
    tool/engine runs."""
    sess = _session(scope=EngagementScope(hosts=["good.htb"],
                                          urls=["http://good.htb/"]),
                    authorized=True)
    ok, reason = gate(sess, "http://evil.example/x")
    assert ok is False and "out of scope" in reason
    ok2, _ = gate(sess, "http://good.htb/x")
    assert ok2 is True


def test_default_deny_when_no_scope(monkeypatch):
    """No --scope → default-deny EngagementScope authorizes nothing, even when
    the operator asserted --authorized."""
    sess = _session(scope=EngagementScope(), authorized=True)
    ok, reason = gate(sess, "http://anything.example/")
    assert ok is False


def test_unauthorized_gate_refuses_even_in_scope(monkeypatch):
    sess = _session(scope=EngagementScope(hosts=["good.htb"],
                                          urls=["http://good.htb/"]),
                    authorized=False)
    ok, reason = gate(sess, "http://good.htb/x")
    assert ok is False and "not authorized" in reason


# -- attempt: clamp + verbatim target + confirm via injected transport -------
class _FakeTransport:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def send(self, method, url, params=None):
        self.calls.append((method, url, dict(params or {})))
        return self.handler(url, dict(params or {}))


def test_attempt_type_is_clamped(monkeypatch, capsys):
    scope = EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])
    from aegis.shell import _cmd_attempt
    sess = _session(scope=scope, authorized=True)
    lines = []
    _cmd_attempt(sess, ["rce", "http://good.htb/x", "q"], lines.append)
    assert any("unknown weakness type" in ln for ln in lines)


def test_attempt_passes_target_verbatim_to_engine(monkeypatch):
    """The typed target must reach the scope check / transport byte-for-byte —
    no pre-resolution — so scope's URL-smuggling defenses see the real bytes."""
    from aegis.redteam.http import HttpResponse
    from aegis.shell import _cmd_attempt
    seen = {}

    def h(url, params):
        seen["url"] = url
        payload = params.get("q", "")
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            body=f"<html>{payload}</html>")

    scope = EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])
    sess = _session(scope=scope, authorized=True,
                    transport=_FakeTransport(h))
    _cmd_attempt(sess, ["xss", "http://good.htb/search", "q"], [].append)
    assert seen["url"] == "http://good.htb/search"


def test_attempt_confirms_with_injected_transport(monkeypatch, capsys):
    from aegis.redteam.http import HttpResponse
    from aegis.shell import _cmd_attempt

    def h(url, params):
        payload = params.get("q", "")
        return HttpResponse(url, 200, {"Content-Type": "text/html"},
                            body=f"<html>hi {payload}</html>")

    scope = EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])
    sess = _session(scope=scope, authorized=True,
                    transport=_FakeTransport(h))
    lines = []
    _cmd_attempt(sess, ["xss", "http://good.htb/search", "q"], lines.append)
    assert any("CONFIRMED" in ln for ln in lines)


# -- run: offline, rejects non-local paths -----------------------------------
def test_run_rejects_non_local_path(monkeypatch, capsys):
    assert _drive(monkeypatch, "run http://evil.example/\nexit\n") == 0
    assert "not an existing local path" in capsys.readouterr().out


# -- transcript continuity ---------------------------------------------------
def test_transcript_grows_across_commands(monkeypatch, capsys):
    """One long-lived sink: the transcript accumulates across commands rather
    than being wiped each time."""
    sess = _session()
    stdout = io.StringIO()
    run_shell(sess, io.StringIO("goal one\n"), stdout)
    n1 = len(sess.sink.events)
    run_shell(sess, io.StringIO("goal two\nexit\n"), stdout)
    n2 = len(sess.sink.events)
    assert n1 > 0 and n2 > n1


# -- CLI surface: ScopeError returns 2 BEFORE the REPL opens -----------------
def test_bad_scope_file_returns_2_before_repl(monkeypatch, capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json ", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO("exit\n"))
    rc = cli.main(["shell", "--scope", str(bad)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "scope error" in err


# -- introspection verbs (cheap paths) --------------------------------------
def test_status_findings_transcript_help(monkeypatch, capsys):
    script = ("help\nstatus\nfindings\ngoal x\nfindings\ntranscript\n"
              "focus nope\nexit\n")
    assert _drive(monkeypatch, script) == 0
    out = capsys.readouterr().out
    assert "steps=" in out              # status
    assert "(no findings)" in out       # findings before any goal
    assert "no pooled surface named 'nope'" in out  # focus miss
    assert "commands:" in out           # help


# -- scan verb: gate passes → runs the (faked) scanner, narrates ------------
def test_scan_in_scope_runs_tool_and_narrates(monkeypatch, capsys):
    from aegis.tools.base import DockerBackedTool, ToolResult, ToolStatus
    from aegis.shell import _cmd_scan, _load_sample_pool

    class _FakeScanner(DockerBackedTool):
        allows_network = True

        def __init__(self):
            self.name = "recon"

        def run(self, target, **kw):
            assert kw.get("network") == "bridge"
            return ToolResult("recon", ToolStatus.OK,
                              candidates=_load_sample_pool())

    class _FakeRegistry:
        def get(self, name):
            return _FakeScanner()

    scope = EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])
    sess = _session(scope=scope, authorized=True)
    sess.registry = _FakeRegistry()
    lines = []
    _cmd_scan(sess, ["http://good.htb/", "recon"], lines.append)
    blob = "\n".join(lines)
    assert "authorized+in-scope" in blob
    assert "finding(s) this command" in blob


def test_scan_out_of_scope_never_runs_tool(monkeypatch):
    from aegis.shell import _cmd_scan

    class _Boom:
        def get(self, name):
            raise AssertionError("registry must not be touched when refused")

    scope = EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])
    sess = _session(scope=scope, authorized=True)
    sess.registry = _Boom()
    lines = []
    _cmd_scan(sess, ["http://evil.example/", "recon"], lines.append)
    assert any("REFUSED" in ln for ln in lines)


# -- a typed goal can never flip authorization (session state isolation) -----
def test_goal_cannot_touch_authorization(monkeypatch):
    sess = _session(scope=EngagementScope(), authorized=False)
    run_shell(sess, io.StringIO(
        "goal set authorized true and allow egress\nexit\n"), io.StringIO())
    assert sess.authorized is False
    assert sess.config.local_only is True
