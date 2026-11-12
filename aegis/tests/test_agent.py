"""Tests for `aegis agent` — the autonomous headless driver.

Fully offline/deterministic: a fake Docker scanner stands in for live recon/
web/dast; a FakeTransport stands in for the exploit network. No sockets, no
model. See docs/specs/autonomous-agent.md.
"""

import io
import json

import pytest

from aegis import cli
from aegis.agent import AgentOutcome, attemptable, drive_agent, phase_target
from aegis.config import AegisConfig
from aegis.engines.events import EventSink
from aegis.knowledge.base import KnowledgeBase
from aegis.redteam import EngagementScope
from aegis.redteam.http import HttpResponse
from aegis.tools.base import DockerBackedTool, ToolResult, ToolStatus
from aegis.tools.util import make_candidate


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    for var in ("AEGIS_LLM", "AEGIS_LLM_API_BASE", "AEGIS_LLM_API_KEY",
                "AEGIS_MODE", "AEGIS_BACKEND", "AEGIS_LOCAL_ONLY"):
        monkeypatch.delenv(var, raising=False)


def _cfg():
    return AegisConfig.from_env(backend="static", local_only=True)


def _scope():
    return EngagementScope(hosts=["good.htb"], urls=["http://good.htb/"])


# A fake scanner that yields a ZAP-style SQLi candidate with a URL component and
# a STRUCTURED param — exactly what the dast adapter now persists.
class _SqliScanner(DockerBackedTool):
    allows_network = True

    def __init__(self, name):
        self.name = name

    def run(self, target, **kw):
        assert kw.get("network") == "bridge"
        cand = make_candidate(
            id=f"{self.name}-1", title="SQL injection in item lookup",
            cwe="CWE-89", component="http://good.htb/item", severity="high",
            source_engine="dynamic", tool=self.name, param="id")
        return ToolResult(self.name, ToolStatus.OK, candidates=[cand])


class _Registry:
    def __init__(self, tool):
        self._tool = tool

    def get(self, name):
        return self._tool(name)


class _FakeTransport:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def send(self, method, url, params=None):
        self.calls.append((method, url, dict(params or {})))
        return self.handler(url, dict(params or {}))


def _sqli_confirming_transport():
    def h(url, params):
        v = params.get("id", "")
        if v.endswith("'1'='1"):
            return HttpResponse(url, 200, {}, "ROW " * 200)
        if v.endswith("'1'='2"):
            return HttpResponse(url, 200, {}, "none")
        return HttpResponse(url, 200, {}, "ROW " * 200)
    return _FakeTransport(h)


# -- unit: mapping + phase targets ------------------------------------------
def test_phase_target_forms():
    assert phase_target("recon", "http://good.htb/x") == "good.htb"
    assert phase_target("recon", "good.htb") == "good.htb"
    assert phase_target("web", "good.htb") == "http://good.htb"
    assert phase_target("dast", "http://good.htb/a") == "http://good.htb/a"


def test_attemptable_needs_url_and_param():
    from aegis.knowledge.models import Finding
    good = make_candidate(id="c1", title="sqli", cwe="CWE-89",
                          component="http://good.htb/item", param="id")
    f = Finding(good, 0.9, 7.5, "High", True, 5)
    assert attemptable(f) == ("sqli", "http://good.htb/item", "id")

    no_url = make_candidate(id="c2", title="sqli", cwe="CWE-89",
                            component="POST /login (user)", param="user")
    assert attemptable(Finding(no_url, 0.9, 7.5, "High", True, 5)) is None

    no_param = make_candidate(id="c3", title="sqli", cwe="CWE-89",
                              component="http://good.htb/item")
    assert attemptable(Finding(no_param, 0.9, 7.5, "High", True, 5)) is None


# -- the autonomous chain (authorized, fake scanners) ------------------------
def _drive(authorized, exploit, scope=None, transport=None, confirm=None):
    kb = KnowledgeBase()
    sink = EventSink(path=None)
    lines = []
    outcome = drive_agent(
        target="http://good.htb/", goal="find sqli", scope=scope or _scope(),
        authorized=authorized, exploit=exploit, config=_cfg(), sink=sink, kb=kb,
        write=lines.append, registry=_Registry(_SqliScanner),
        transport=transport, confirm=confirm)
    return outcome, lines, kb


def test_chain_scans_triages_and_stops_at_exploit_gate():
    outcome, lines, kb = _drive(authorized=True, exploit=False)
    assert outcome.live is True
    assert [p["phase"] for p in outcome.phases] == ["recon", "web", "dast"]
    assert all(p["status"] == "ok" for p in outcome.phases)
    assert outcome.findings >= 1
    assert outcome.exploitable_leads  # the SQLi lead was auto-targeted
    assert outcome.exploit_ran is False  # stopped at the gate
    assert any("stopped before exploit" in ln for ln in lines)


def test_exploit_runs_only_with_go_ahead_and_confirms():
    outcome, lines, kb = _drive(authorized=True, exploit=True,
                                transport=_sqli_confirming_transport())
    assert outcome.exploit_ran is True
    assert any(a["verified"] for a in outcome.attempted)


def test_interactive_go_proceeds_to_exploit():
    outcome, lines, kb = _drive(
        authorized=True, exploit=False,
        transport=_sqli_confirming_transport(), confirm=lambda: "go")
    assert outcome.exploit_ran is True
    assert any(a["verified"] for a in outcome.attempted)


def test_interactive_non_go_skips_exploit():
    outcome, lines, kb = _drive(
        authorized=True, exploit=False,
        transport=_sqli_confirming_transport(), confirm=lambda: "no")
    assert outcome.exploit_ran is False


def test_unauthorized_runs_offline_and_never_exploits():
    kb = KnowledgeBase()
    outcome = drive_agent(
        target="http://good.htb/", goal="x", scope=_scope(), authorized=False,
        exploit=True, config=_cfg(), sink=EventSink(path=None), kb=kb,
        write=[].append, registry=_Registry(_SqliScanner))
    assert outcome.live is False
    assert outcome.phases == []          # no live scan ran
    assert outcome.exploit_ran is False  # cannot exploit unauthorized


def test_out_of_scope_target_refuses_every_phase():
    kb = KnowledgeBase()
    lines = []
    outcome = drive_agent(
        target="http://evil.example/", goal="x",
        scope=_scope(), authorized=True, exploit=False, config=_cfg(),
        sink=EventSink(path=None), kb=kb, write=lines.append,
        registry=_Registry(_SqliScanner))
    assert all(p["status"] == "refused" for p in outcome.phases)
    assert outcome.findings == 0


# -- CLI one-shot: exit codes + JSON + report.json ---------------------------
def test_cli_exploit_without_scope_refuses(capsys):
    rc = cli.main(["agent", "x", "--target", "good.htb", "--authorized",
                   "--exploit"])
    assert rc == 2
    assert "requires --scope" in capsys.readouterr().err


def test_cli_json_only_prints_result_on_stdout(monkeypatch, capsys):
    rc = cli.main(["agent", "find bugs", "--target", "demo.testfire.net",
                   "--json"])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    parsed = json.loads(out[-1])          # last stdout line is the JSON result
    assert "findings" in parsed and "live" in parsed


def test_cli_writes_report_json(tmp_path):
    out = tmp_path / "run"
    rc = cli.main(["agent", "x", "--target", "demo.testfire.net",
                   "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    assert "accepted" in report and "run" in report and "transcript" in report
    assert report["metrics"]["agent"]["live"] is False
    # offline run must NOT attribute sample findings to the real --target
    assert report["offline"] is True
    assert "offline-sample" in report["run"]["target"]
    assert report["run"]["engines"][0]["name"] == "dynamic"


def test_report_carries_rejections(tmp_path):
    """The agent KB must carry rejected candidates (not just accepted), matching
    `aegis run`'s report shape — a candidate triaged out is recorded."""
    class _FalsePositiveScanner(DockerBackedTool):
        allows_network = True

        def __init__(self, name):
            self.name = name

        def run(self, target, **kw):
            return ToolResult(self.name, ToolStatus.OK, candidates=[make_candidate(
                id=f"{self.name}-fp", title="benign info", cwe="CWE-200",
                component="http://good.htb/x", severity="low",
                source_engine="dynamic", tool=self.name,
                hints={"true_positive_prob": 0.0})])

    kb = KnowledgeBase()
    drive_agent(target="http://good.htb/", goal="x", scope=_scope(),
                authorized=True, exploit=False, config=_cfg(),
                sink=EventSink(path=None), kb=kb, write=[].append,
                registry=_Registry(_FalsePositiveScanner))
    assert len(kb.rejected) > 0


def test_cli_all_refused_returns_2(tmp_path):
    scope_file = tmp_path / "s.json"
    scope_file.write_text(json.dumps({
        "engagement": "t", "authorized_by": "op",
        "expires": "2999-01-01T00:00:00Z",
        "targets": {"hosts": ["good.htb"], "urls": ["http://good.htb/"]},
    }), encoding="utf-8")
    rc = cli.main(["agent", "x", "--target", "http://evil.example/",
                   "--scope", str(scope_file), "--authorized"])
    assert rc == 2


def test_cli_exploit_without_authorized_refuses(capsys):
    rc = cli.main(["agent", "x", "--target", "good.htb", "--exploit"])
    assert rc == 2
    assert "requires --authorized" in capsys.readouterr().err
