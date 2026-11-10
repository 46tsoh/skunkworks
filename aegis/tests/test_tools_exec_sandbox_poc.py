"""Tests for the exec-sandbox-poc dynamic adapters: shell, sandbox, poc.

All offline. The Docker-backed path (shell, sandbox) is exercised via
availability checks and a monkeypatched ``run_container``; the host-local path
(poc) via ``shutil.which`` and a monkeypatched ``runtime.run_local``. No binary,
no container, no network is ever touched.
"""

import shutil

import pytest

from aegis.tools import runtime
from aegis.tools.adapters import poc, sandbox, shell
from aegis.tools.base import ToolKind, ToolStatus
from aegis.tools.runtime import ContainerRun


# =====================================================================
# shell (Docker-backed, dynamic)
# =====================================================================
def test_shell_fixture_parses_candidates():
    tool = shell.make_fixture()
    assert tool.available()
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"shell-1", "shell-2", "shell-3"}
    cmdi = next(c for c in result.candidates if c.id == "shell-1")
    assert cmdi.cwe == "CWE-78"
    assert cmdi.component == "scripts/deploy.sh:47"
    assert cmdi.source_engine == "dynamic"
    assert cmdi.metadata["tool"] == "shell"
    assert cmdi.cvss_vector  # derived from severity by make_candidate
    # CWE-78 -> OWASP injection category.
    assert cmdi.owasp.startswith("A03")


def test_shell_parse_handles_empty():
    assert shell.parse("", "t") == []
    assert shell.parse("banner only\nno findings here\n", "t") == []


def test_shell_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = shell.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_shell_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = shell.make_docker()
    assert tool.available() is False
    assert tool.run("data/sample_target").status == ToolStatus.UNAVAILABLE


def test_shell_ok_when_image_present(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_text = shell._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    result = shell.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == shell.IMAGE


def test_shell_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    def boom(*a, **k):
        raise RuntimeError("container exploded")
    monkeypatch.setattr(base, "run_container", boom)
    result = shell.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "container exploded" in result.errors[0]


# =====================================================================
# sandbox (Docker-backed, dynamic)
# =====================================================================
def test_sandbox_fixture_parses_candidates():
    tool = sandbox.make_fixture()
    assert tool.available()
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"sandbox-1", "sandbox-2"}  # only confirmed, not unconfirmed
    deser = next(c for c in result.candidates if c.id == "sandbox-1")
    assert deser.cwe == "CWE-502"
    assert deser.component == "app/tasks/worker.py:88"
    assert deser.source_engine == "dynamic"
    assert deser.metadata["tool"] == "sandbox"
    assert deser.metadata["reproduced"] is True
    assert deser.cvss_vector


def test_sandbox_parse_handles_empty():
    assert sandbox.parse("", "t") == []
    assert sandbox.parse('{"confirmed": []}', "t") == []


def test_sandbox_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = sandbox.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_sandbox_ok_when_image_present(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_text = sandbox._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    result = sandbox.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 2
    assert result.metadata["image"] == sandbox.IMAGE


def test_sandbox_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    def boom(*a, **k):
        raise RuntimeError("sandbox exploded")
    monkeypatch.setattr(base, "run_container", boom)
    result = sandbox.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "sandbox exploded" in result.errors[0]


# =====================================================================
# poc (host-local, dynamic)
# =====================================================================
def test_poc_fixture_parses_candidates():
    tool = poc.make_fixture()
    assert tool.available()
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"poc-1", "poc-2"}
    sqli = next(c for c in result.candidates if c.id == "poc-1")
    assert sqli.cwe == "CWE-89"
    assert sqli.component == "api/auth/login.py:42"
    assert sqli.source_engine == "dynamic"
    assert sqli.metadata["tool"] == "poc"
    # The candidate carries the proof in evidence + metadata (proves, not scores).
    assert sqli.metadata["poc_proof"].startswith("POST /login")
    assert sqli.metadata["reproduced"] is True
    assert any("PoC proof:" in e for e in sqli.evidence)
    assert sqli.cvss_vector


def test_poc_parse_handles_empty():
    assert poc.parse("", "t") == []
    assert poc.parse('{"generated": []}', "t") == []


def test_poc_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    tool = poc.make_host()
    assert tool.available() is False
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "python3" in result.errors[0]


def test_poc_ok_when_binary_present(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/python3")
    fixture_text = poc._FIXTURE.read_text()
    monkeypatch.setattr(runtime, "run_local",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    tool = poc.make_host()
    assert tool.available() is True
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 2
    assert result.metadata["binary"] == "python3"


def test_poc_error_is_caught(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/python3")
    def boom(*a, **k):
        raise RuntimeError("poc driver exploded")
    monkeypatch.setattr(runtime, "run_local", boom)
    result = poc.make_host().run("t")
    assert result.status == ToolStatus.ERROR
    assert "poc driver exploded" in result.errors[0]


# =====================================================================
# shared shape assertions
# =====================================================================
@pytest.mark.parametrize("mod", [shell, sandbox, poc])
def test_adapters_are_dynamic(mod):
    assert mod.make_fixture().kind == ToolKind.DYNAMIC


def test_result_as_dict_is_json_safe():
    for mod in (shell, sandbox, poc):
        d = mod.make_fixture().run("t").as_dict()
        assert d["status"] == "ok"
        assert isinstance(d["candidates"], list)
        assert d["candidate_count"] == len(d["candidates"])
