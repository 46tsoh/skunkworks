"""Tests for the git-history forensics adapter (containerised, static).

All offline: the live gitleaks path is exercised through availability checks and
a monkeypatched ``run_container`` that returns the recorded fixture, never by
pulling the image or touching a real repository. Running gitleaks in a
container (target mounted read-only, no network) is what keeps a hostile target
repo from executing on the host.
"""

from aegis.tools.adapters import forensics
from aegis.tools.base import ToolKind, ToolStatus
from aegis.tools.runtime import ContainerRun


# -- parser (the bug-prone part) ---------------------------------------------
def test_forensics_fixture_parses_candidates():
    tool = forensics.make_fixture()
    assert tool.available()
    result = tool.run("data/sample_repo")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"forensics-1", "forensics-2", "forensics-3"}

    aws = next(c for c in result.candidates if c.id == "forensics-1")
    assert aws.cwe == "CWE-798"
    assert aws.component == "config/settings.py:12"
    assert aws.source_engine == "static"
    assert aws.metadata["tool"] == "forensics"
    assert aws.metadata["rule"] == "aws-access-token"
    assert aws.metadata["commit"].startswith("a1b2c3d4")
    assert aws.owasp.startswith("A07")  # CWE-798 -> identification/auth failures

    # The raw secret value never travels into a candidate; only its length does.
    joined = " ".join(aws.evidence)
    assert "AKIAIOSFODNN7EXAMPLE" not in joined
    assert "redacted secret" in joined


def test_forensics_parse_handles_empty():
    assert forensics.parse("", "t") == []
    assert forensics.parse("[]", "t") == []
    assert forensics.parse('{"findings": []}', "t") == []


def test_forensics_parse_tolerates_sparse_finding():
    cands = forensics.parse('[{"RuleID": "generic-api-key"}]', "t")
    assert len(cands) == 1
    assert cands[0].cwe == "CWE-798"
    assert cands[0].component == "?:0"


# -- containerised execution (no host gitleaks/git, no image pull) -----------
def test_forensics_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = forensics.make_docker().run("data/sample_repo")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []


def test_forensics_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    assert forensics.make_docker().available() is False
    assert forensics.make_docker().run("x").status == ToolStatus.UNAVAILABLE


def test_forensics_parses_when_image_present(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_json = forensics._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_json, ""))
    result = forensics.make_docker().run("data")  # a real, mountable dir
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == forensics.IMAGE


def test_forensics_missing_target_is_error(monkeypatch):
    # Needs a mounted repo: a missing target is ERROR, never a silent clean scan.
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    result = forensics.make_docker().run("data/does-not-exist")
    assert result.status == ToolStatus.ERROR
    assert "not found" in result.errors[0]


def test_forensics_nonzero_exit_is_error(monkeypatch):
    # A non-zero gitleaks exit (we force --exit-code 0) is a real failure.
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(128, "", "fatal: not a repo"))
    result = forensics.make_docker().run("data")
    assert result.status == ToolStatus.ERROR
    assert result.candidates == []
    assert "exit code 128" in result.errors[0]


def test_forensics_runs_read_only_no_network(monkeypatch):
    # The container is launched read-only + no-network: capture the real argv.
    import subprocess
    import aegis.tools.runtime as rt
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr(rt.subprocess, "run", fake_run)
    rt.run_container(forensics.IMAGE, forensics.make_docker().argv("/work"),
                     mounts=[("data", "/work")])
    cmd = captured["cmd"]
    assert "--network=none" in cmd
    assert "--pull=never" in cmd
    assert any(p.endswith(":/work:ro") for p in cmd)  # read-only mount


def test_forensics_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("gitleaks exploded")
    monkeypatch.setattr(base, "run_container", boom)
    result = forensics.make_docker().run("data")
    assert result.status == ToolStatus.ERROR
    assert "gitleaks exploded" in result.errors[0]


def test_forensics_kind_is_static():
    assert forensics.make_docker().kind == ToolKind.STATIC
    assert forensics.make_fixture().kind == ToolKind.STATIC
