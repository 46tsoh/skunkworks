"""Tests for the binary / fuzz / crash static adapters (group: binary-fuzz-crash).

All offline: parsers are exercised over recorded fixtures, and the Docker-backed
path is driven through monkeypatched availability + runtime — no image is pulled
and no network is touched.
"""

import pytest

from aegis.tools.adapters import binary, crash, fuzz
from aegis.tools.base import ToolKind, ToolStatus
from aegis.tools.runtime import ContainerRun

# (module, expected candidate count, kind) for the shared, table-driven checks.
ADAPTERS = [
    (binary, 8, ToolKind.STATIC),
    (fuzz, 3, ToolKind.STATIC),
    (crash, 3, ToolKind.STATIC),
]


# -- parsers (the bug-prone part) --------------------------------------------
def test_binary_fixture_parses_candidates():
    tool = binary.make_fixture()
    assert tool.available()
    result = tool.run("bin/vault-authd")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {f"binary-{i}" for i in range(1, 9)}
    canary = next(c for c in result.candidates if "canary" in c.title)
    assert canary.cwe == "CWE-693"
    assert canary.component == "bin/vault-authd"
    assert canary.source_engine == "static"
    assert canary.metadata["tool"] == "binary"
    # system() is command-injection class and maps onto OWASP A03.
    system = next(c for c in result.candidates if c.title.startswith("Unsafe imported function: system"))
    assert system.cwe == "CWE-78"
    assert system.owasp.startswith("A03")
    # NX is enabled in the fixture, so it must NOT be reported as missing.
    assert not any("NX" in c.title for c in result.candidates)


def test_fuzz_fixture_parses_candidates():
    tool = fuzz.make_fixture()
    assert tool.available()
    result = tool.run("bin/parse_record")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"fuzz-1", "fuzz-2", "fuzz-3"}
    first = next(c for c in result.candidates if c.id == "fuzz-1")
    assert first.cwe == "CWE-787"                       # SIGSEGV -> OOB write class
    assert first.component == "bin/parse_record:crash-000000"
    assert first.source_engine == "static"
    assert first.metadata["tool"] == "fuzz"
    assert first.metadata["signal"] == "SIGSEGV"


def test_crash_fixture_parses_candidates():
    tool = crash.make_fixture()
    assert tool.available()
    result = tool.run("bin/parse_record")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"crash-1", "crash-2", "crash-3"}
    exploitable = next(c for c in result.candidates if c.id == "crash-1")
    assert exploitable.cwe == "CWE-787"
    assert exploitable.component == "bin/parse_record:process_token"
    assert exploitable.metadata["classification"] == "EXPLOITABLE"
    assert exploitable.metadata["exploitable_hint"] is True
    # Severity drives the default CVSS vector: EXPLOITABLE -> critical (C:H/I:H/A:H).
    assert "C:H/I:H/A:H" in exploitable.cvss_vector
    assert exploitable.source_engine == "static"
    # CWE from the entry is preserved; canary trip keeps its CWE-121.
    canary = next(c for c in result.candidates if c.id == "crash-2")
    assert canary.cwe == "CWE-121"


@pytest.mark.parametrize("mod", [binary, fuzz, crash])
def test_every_candidate_has_a_cvss_vector(mod):
    # make_candidate must derive a vector from severity when the tool gives none.
    for c in mod.parse(mod._FIXTURE.read_text(), "t"):
        assert c.cvss_vector and c.cvss_vector.startswith("AV:")


@pytest.mark.parametrize("mod", [binary, fuzz, crash])
def test_parse_handles_empty(mod):
    assert mod.parse("", "t") == []
    assert mod.parse("{}", "t") == []


# -- availability degradation (no image / no docker) -------------------------
@pytest.mark.parametrize("mod,_count,_kind", ADAPTERS)
def test_docker_tool_unavailable_without_image(monkeypatch, mod, _count, _kind):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = mod.make_docker().run("bin/target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


@pytest.mark.parametrize("mod,_count,_kind", ADAPTERS)
def test_docker_tool_unavailable_without_daemon(monkeypatch, mod, _count, _kind):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = mod.make_docker()
    assert tool.available() is False
    assert tool.run("bin/target").status == ToolStatus.UNAVAILABLE


# -- live path simulated via monkeypatched runtime ---------------------------
@pytest.mark.parametrize("mod,count,kind", ADAPTERS)
def test_docker_tool_parses_when_image_present(monkeypatch, mod, count, kind):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_text = mod._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    result = mod.make_docker().run("bin/target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == count
    assert result.metadata["image"] == mod.IMAGE
    assert mod.make_docker().kind == kind
    for c in result.candidates:
        assert c.metadata["tool"] == mod.make_docker().name


# -- error path is caught, never raised --------------------------------------
@pytest.mark.parametrize("mod,_count,_kind", ADAPTERS)
def test_docker_tool_error_is_caught(monkeypatch, mod, _count, _kind):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("docker exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = mod.make_docker().run("bin/target")
    assert result.status == ToolStatus.ERROR
    assert "docker exploded" in result.errors[0]


# -- malformed native output surfaces as ERROR, not a crash ------------------
@pytest.mark.parametrize("mod,_count,_kind", ADAPTERS)
def test_bad_json_is_error_via_fixture(monkeypatch, mod, _count, _kind, tmp_path):
    from aegis.tools.base import FixtureTool
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    tool = FixtureTool(mod.make_fixture().name, ToolKind.STATIC, bad, mod.parse)
    result = tool.run("t")
    assert result.status == ToolStatus.ERROR
    assert result.errors
