"""Tests for the Tool interface, the semgrep reference adapter, and the registry.

All offline: the Docker-backed path is exercised through availability checks and
monkeypatched runtime, never by pulling images.
"""

import pytest

from aegis.tools import default_registry
from aegis.tools.adapters import semgrep
from aegis.tools.base import (
    DockerBackedTool,
    FixtureTool,
    ToolKind,
    ToolRegistry,
    ToolStatus,
)


# -- semgrep parser (the bug-prone part) -------------------------------------
def test_semgrep_fixture_parses_candidates():
    tool = semgrep.make_fixture()
    assert tool.available()
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"semgrep-1", "semgrep-2", "semgrep-3"}
    sqli = next(c for c in result.candidates if c.id == "semgrep-1")
    assert sqli.cwe == "CWE-89"
    assert sqli.component == "api/auth/login.py:42"
    assert sqli.source_engine == "static"
    assert sqli.metadata["tool"] == "semgrep"
    assert sqli.owasp.startswith("A03")  # CWE-89 -> injection


def test_semgrep_parse_handles_empty():
    assert semgrep.parse("", "t") == []
    assert semgrep.parse('{"results": []}', "t") == []


def test_semgrep_argv_is_offline_and_uses_rules_volume():
    """Semgrep must never fetch rules from the network (--config auto). It uses
    the provisioned read-only rules volume, selecting curated language dirs,
    with metrics off."""
    tool = semgrep.make_docker()
    argv = tool.argv("/work")
    assert argv[0] == "semgrep"
    assert "auto" not in argv                      # never the network ruleset
    assert "--metrics=off" in argv                 # no phone-home
    # every --config points inside the mounted rules volume
    cfgs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert cfgs and all(c.startswith(tool.RULES_DIR + "/") for c in cfgs)
    assert f"{tool.RULES_DIR}/python" in cfgs
    assert tool.volumes() == [(tool.RULES_VOLUME, tool.RULES_DIR)]


def test_semgrep_argv_config_override():
    # An explicit config (e.g. a single ruleset) overrides the curated set.
    argv = semgrep.make_docker().argv("/work", config="/rules/python")
    assert argv.count("--config") == 1
    assert argv[argv.index("--config") + 1] == "/rules/python"


def test_semgrep_rules_volume_mounted_readonly(monkeypatch):
    import aegis.tools.base as base
    from aegis.tools.runtime import ContainerRun
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    captured = {}
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: (captured.update(k)
                                         or ContainerRun(0, '{"results": []}', "")))
    semgrep.make_docker().run("data/sample_target")
    assert captured["volumes"] == [("aegis-semgrep-rules", "/rules")]


# -- availability degradation (no image / no docker) -------------------------
def test_docker_tool_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    tool = semgrep.make_docker()
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_docker_tool_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = semgrep.make_docker()
    assert tool.available() is False
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE


def test_docker_tool_parses_when_image_present(monkeypatch):
    # Simulate a live container run without pulling an image.
    import aegis.tools.base as base
    from aegis.tools.runtime import ContainerRun
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_json = semgrep._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_json, ""))
    result = semgrep.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == semgrep.IMAGE


def test_docker_tool_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    def boom(*a, **k):
        raise RuntimeError("docker exploded")
    monkeypatch.setattr(base, "run_container", boom)
    result = semgrep.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "docker exploded" in result.errors[0]


# -- registry ----------------------------------------------------------------
def test_registry_register_and_query():
    reg = ToolRegistry()
    reg.register(semgrep.make_fixture())
    assert "semgrep" in reg.names()
    assert reg.by_kind(ToolKind.STATIC)
    with pytest.raises(ValueError):
        reg.register(semgrep.make_fixture())  # dup without replace
    reg.register(semgrep.make_fixture(), replace=True)  # ok


def test_default_registry_is_runnable_offline():
    # Without a built image, the fixture adapter keeps the slot and runs.
    reg = default_registry(prefer_docker=False)
    assert "semgrep" in reg.names()
    result = reg.run("semgrep", "data/sample_target")
    assert result.status == ToolStatus.OK
    report = reg.status_report()
    assert report["semgrep"]["kind"] == "static"


def test_result_as_dict_is_json_safe():
    result = semgrep.make_fixture().run("t")
    d = result.as_dict()
    assert d["candidate_count"] == 3
    assert isinstance(d["candidates"], list)
    assert d["status"] == "ok"
