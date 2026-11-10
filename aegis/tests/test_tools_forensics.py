"""Tests for the git-history forensics adapter (host-local, static).

All offline: the live gitleaks path is exercised through availability checks and
a monkeypatched ``runtime.run_local`` that returns the recorded fixture, never by
installing gitleaks or touching a real repository.
"""

import shutil

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
    # A finding missing most fields must not crash the parser.
    cands = forensics.parse('[{"RuleID": "generic-api-key"}]', "t")
    assert len(cands) == 1
    assert cands[0].cwe == "CWE-798"
    assert cands[0].component == "?:0"


# -- availability degradation (git binary absent) ----------------------------
def test_host_tool_unavailable_without_git(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: None)
    tool = forensics.make_host()
    assert tool.available() is False
    result = tool.run("data/sample_repo")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "git" in result.errors[0]


# -- OK path when git present (run_local monkeypatched to the fixture) --------
def test_host_tool_parses_when_git_present(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")
    fixture_json = forensics._FIXTURE.read_text()
    monkeypatch.setattr(forensics.runtime, "run_local",
                        lambda *a, **k: ContainerRun(0, fixture_json, ""))
    result = forensics.make_host().run("data/sample_repo")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["scanner"] == "gitleaks"
    assert result.metadata["scanner_present"] is True


def test_host_tool_timeout_is_error(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(forensics.runtime, "run_local",
                        lambda *a, **k: ContainerRun(124, "", "", timed_out=True))
    result = forensics.make_host().run("data/sample_repo")
    assert result.status == ToolStatus.ERROR
    assert result.errors == ["timed out"]


# -- ERROR path (exception from the subprocess layer is caught) --------------
def test_host_tool_error_is_caught(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")

    def boom(*a, **k):
        raise RuntimeError("gitleaks exploded")

    monkeypatch.setattr(forensics.runtime, "run_local", boom)
    result = forensics.make_host().run("data/sample_repo")
    assert result.status == ToolStatus.ERROR
    assert "gitleaks exploded" in result.errors[0]


def test_forensics_kind_is_static():
    assert forensics.make_host().kind == ToolKind.STATIC
    assert forensics.make_fixture().kind == ToolKind.STATIC
