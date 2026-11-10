"""Tests for the dynamic instrumentation adapters: frida and rr.

All offline: the Docker-backed path is exercised through availability checks and
a monkeypatched runtime, never by pulling images or launching a process. Both
tools are ``ToolKind.DYNAMIC`` and emit ``source_engine == "dynamic"`` candidates.
"""

import pytest

from aegis.tools.adapters import frida, rr
from aegis.tools.base import ToolKind, ToolStatus
from aegis.tools.runtime import ContainerRun


# -- frida parser ------------------------------------------------------------
def test_frida_fixture_parses_candidates():
    tool = frida.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.DYNAMIC
    result = tool.run("bin/vulnserver")
    assert result.status == ToolStatus.OK
    # Only the four tainted sink calls become candidates; the untainted
    # getenv("PATH") observation is dropped.
    ids = {c.id for c in result.candidates}
    assert ids == {"frida-1", "frida-2", "frida-3", "frida-4"}

    cmd = next(c for c in result.candidates if c.id == "frida-1")
    assert cmd.cwe == "CWE-78"
    assert cmd.component == "libc.so.6!system"
    assert cmd.source_engine == "dynamic"
    assert cmd.metadata["tool"] == "frida"
    assert cmd.metadata["taint_source"] == "http.query.host"
    assert cmd.owasp.startswith("A03")  # CWE-78 -> injection

    sqli = next(c for c in result.candidates if c.id == "frida-2")
    assert sqli.cwe == "CWE-89"
    assert sqli.component == "libsqlite3.so.0!sqlite3_exec"

    traversal = next(c for c in result.candidates if c.id == "frida-3")
    assert traversal.cwe == "CWE-22"
    assert traversal.component == "libc.so.6!fopen"

    # Explicit per-hook cwe overrides the category default.
    overflow = next(c for c in result.candidates if c.id == "frida-4")
    assert overflow.cwe == "CWE-120"
    assert "getenv" not in {c.component.split("!")[-1] for c in result.candidates}


def test_frida_parse_handles_empty():
    assert frida.parse("", "t") == []
    assert frida.parse('{"hooks": []}', "t") == []


# -- rr parser ---------------------------------------------------------------
def test_rr_fixture_parses_candidates():
    tool = rr.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.DYNAMIC
    result = tool.run("vulnserver-0")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"rr-1", "rr-2", "rr-3", "rr-4"}

    uaf = next(c for c in result.candidates if c.id == "rr-1")
    assert uaf.cwe == "CWE-416"
    assert uaf.component == "src/cache.c:212 (free_entry)"
    assert uaf.source_engine == "dynamic"
    assert uaf.metadata["tool"] == "rr"
    assert uaf.metadata["fault_class"] == "use-after-free"

    race = next(c for c in result.candidates if c.id == "rr-2")
    assert race.cwe == "CWE-362"

    uninit = next(c for c in result.candidates if c.id == "rr-3")
    assert uninit.cwe == "CWE-457"

    # Explicit per-finding cwe overrides the class default.
    dfree = next(c for c in result.candidates if c.id == "rr-4")
    assert dfree.cwe == "CWE-415"


def test_rr_parse_handles_empty():
    assert rr.parse("", "t") == []
    assert rr.parse('{"findings": []}', "t") == []


# -- availability degradation (no image / no docker) -------------------------
@pytest.mark.parametrize("mod", [frida, rr])
def test_docker_tool_unavailable_without_image(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = mod.make_docker().run("bin/vulnserver")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


@pytest.mark.parametrize("mod", [frida, rr])
def test_docker_tool_unavailable_without_daemon(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = mod.make_docker()
    assert tool.available() is False
    result = tool.run("bin/vulnserver")
    assert result.status == ToolStatus.UNAVAILABLE


# -- OK path via a monkeypatched container run -------------------------------
@pytest.mark.parametrize("mod", [frida, rr])
def test_docker_tool_parses_when_image_present(monkeypatch, mod):
    # Simulate a live container run returning the recorded trace, no image pull.
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_text = mod._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    result = mod.make_docker().run("bin/vulnserver")
    assert result.status == ToolStatus.OK
    assert result.candidates
    assert all(c.source_engine == "dynamic" for c in result.candidates)
    assert result.metadata["image"] == mod.IMAGE


# -- ERROR path is caught, never raised --------------------------------------
@pytest.mark.parametrize("mod", [frida, rr])
def test_docker_tool_error_is_caught(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("container exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = mod.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "container exploded" in result.errors[0]


# -- fixture tools are the dynamic kind and json-safe ------------------------
@pytest.mark.parametrize("mod", [frida, rr])
def test_result_as_dict_is_json_safe(mod):
    result = mod.make_fixture().run("t")
    d = result.as_dict()
    assert d["status"] == "ok"
    assert d["candidate_count"] == len(result.candidates)
    assert isinstance(d["candidates"], list)
