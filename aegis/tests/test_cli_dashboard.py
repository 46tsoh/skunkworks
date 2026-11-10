"""Test the one-command end-to-end interop (`aegis dashboard --no-serve`)."""

import json

import aegis.cli as cli


def test_dashboard_no_serve_writes_unified_run(tmp_path, monkeypatch):
    # Redirect the repo root so the command writes into a temp ui/public/data
    # instead of the committed demo data.
    monkeypatch.setattr(cli, "_REPO_ROOT", tmp_path)
    rc = cli.main(["dashboard", "--no-serve", "--serial", "--run-id", "d1"])
    assert rc == 0
    report = json.loads((tmp_path / "ui" / "public" / "data" / "report.json").read_text())
    assert report["run"]["run_id"] == "d1"
    # both engines ran and findings merged into one ranked report
    assert {e["name"] for e in report["run"]["engines"]} == {"dynamic", "static"}
    assert report["metrics"]["accepted"] >= 1
    assert report["metrics"]["cross_engine_dedup"] == 1
    assert (tmp_path / "ui" / "public" / "data" / "decisions.jsonl").exists()


def test_dashboard_no_serve_with_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_REPO_ROOT", tmp_path)
    rc = cli.main(["dashboard", "--no-serve", "--serial", "--use-tools",
                   "--run-id", "d2"])
    assert rc == 0
    report = json.loads((tmp_path / "ui" / "public" / "data" / "report.json").read_text())
    # tool-sourced candidates from both kinds flowed through to findings
    engines = report["summary"]["engine_counts"]
    assert engines.get("dynamic", 0) > 0 and engines.get("static", 0) > 0


def test_scan_refuses_without_authorization(capsys):
    """`aegis scan` must refuse an external target unless --authorized is set —
    it never touches the network in the refusal path."""
    import aegis.cli as cli
    rc = cli.main(["scan", "--target", "example.com", "--tool", "recon"])
    assert rc == 2
    err = capsys.readouterr().err.lower()
    assert "authorized" in err and "network" in err


def test_scan_runs_agent_loop_and_writes_dashboard(tmp_path, monkeypatch):
    """`aegis scan --out` drives the real findings through the dynamic agent
    loop and writes a dashboard-ready run (report + transcript + events)."""
    import aegis.cli as cli
    import aegis.tools as tools_mod
    from aegis.tools.base import DockerBackedTool, ToolKind, ToolResult, ToolStatus
    from aegis.tools.util import make_candidate

    class FakeScanner(DockerBackedTool):
        name, kind, image = "recon", ToolKind.DYNAMIC, "img:1"
        allows_network = True
        def argv(self, target, **o):
            return ["nmap"]
        def run(self, target, *, network="none", **o):  # no docker/network
            c = make_candidate(id="recon-1", title="Exposed ssh on tcp/22",
                               cwe="CWE-200", component=f"{target}:22",
                               severity="low", description="open", evidence=["x"],
                               source_engine="dynamic", tool="recon")
            return ToolResult("recon", ToolStatus.OK, candidates=[c], target=target)

    class FakeReg:
        def get(self, name):
            return FakeScanner(parser=lambda raw, t: [])

    monkeypatch.setattr(tools_mod, "default_registry", lambda *a, **k: FakeReg())
    out = tmp_path / "data"
    rc = cli.main(["scan", "--target", "scanme.example", "--tool", "recon",
                   "--authorized", "--run-id", "s1", "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    assert report["run"]["target"] == "scanme.example"
    # the agent loop produced a transcript over the real finding
    assert any(e["type"] == "finding" for e in report["transcript"])
    assert (out / "events.jsonl").exists()
