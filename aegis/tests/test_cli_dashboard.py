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
