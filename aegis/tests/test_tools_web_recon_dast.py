"""Tests for the dynamic web-recon-dast adapters (recon/nmap, web/nuclei, dast/ZAP).

All offline: parsers are exercised over recorded native-output fixtures, and the
Docker-backed path is driven through availability checks and a monkeypatched
runtime — never by pulling an image or opening a socket.
"""

import pytest

from aegis.tools.adapters import dast, recon, web
from aegis.tools.base import ToolKind, ToolRegistry, ToolStatus
from aegis.tools.runtime import ContainerRun


# -- recon (nmap XML) --------------------------------------------------------
def test_recon_fixture_parses_open_ports():
    tool = recon.make_fixture()
    assert tool.available()
    result = tool.run("127.0.0.1")
    assert result.status == ToolStatus.OK
    # Only the three OPEN ports become candidates; the closed 443 is dropped.
    ids = {c.id for c in result.candidates}
    assert ids == {"recon-1", "recon-2", "recon-3"}
    ssh = next(c for c in result.candidates if c.id == "recon-1")
    assert ssh.cwe == "CWE-200"
    assert ssh.component == "127.0.0.1:22"
    assert ssh.source_engine == "dynamic"
    assert ssh.metadata["tool"] == "recon"
    assert ssh.metadata["service"] == "ssh"
    assert ssh.cvss_vector  # derived from severity by make_candidate
    mysql = next(c for c in result.candidates if c.component == "127.0.0.1:3306")
    assert "mysql" in mysql.title.lower()


def test_recon_parse_handles_empty():
    assert recon.parse("", "t") == []
    assert recon.parse("   ", "t") == []


def test_recon_parse_rejects_dtd():
    # XXE / billion-laughs hardening: any DTD/entity declaration is refused.
    with pytest.raises(ValueError):
        recon.parse('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>', "t")


# -- web (nuclei JSONL) ------------------------------------------------------
def test_web_fixture_parses_findings():
    tool = web.make_fixture()
    assert tool.available()
    result = tool.run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"web-1", "web-2", "web-3", "web-4"}
    log4j = next(c for c in result.candidates if c.id == "web-3")
    assert log4j.cwe == "CWE-502"
    assert log4j.component == "http://127.0.0.1:8080/api/login"
    assert log4j.source_engine == "dynamic"
    assert log4j.metadata["tool"] == "web"
    assert "CVE-2021-44228" in log4j.metadata["cve"]
    # A finding with no classification CWE falls back to the shared default.
    hsts = next(c for c in result.candidates if c.id == "web-4")
    assert hsts.cwe == "CWE-693"


def test_web_parse_handles_empty_and_garbage():
    assert web.parse("", "t") == []
    assert web.parse("\n  \n", "t") == []
    # A stray non-JSON log line is skipped, valid lines still parse.
    cands = web.parse('not json\n{"template-id":"x","info":{"name":"X","severity":"low"},'
                       '"matched-at":"http://h/a"}\n', "t")
    assert len(cands) == 1
    assert cands[0].component == "http://h/a"


# -- dast (OWASP ZAP JSON) ---------------------------------------------------
def test_dast_fixture_parses_alerts():
    tool = dast.make_fixture()
    assert tool.available()
    result = tool.run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"dast-1", "dast-2", "dast-3"}
    sqli = next(c for c in result.candidates if c.id == "dast-1")
    assert sqli.cwe == "CWE-89"
    assert sqli.component == "http://127.0.0.1:8080/login"
    assert sqli.source_engine == "dynamic"
    assert sqli.metadata["tool"] == "dast"
    assert sqli.owasp.startswith("A03")  # CWE-89 -> injection
    traversal = next(c for c in result.candidates if c.id == "dast-2")
    assert traversal.cwe == "CWE-22"
    assert traversal.owasp.startswith("A01")  # broken access control


def test_dast_parse_handles_empty():
    assert dast.parse("", "t") == []
    assert dast.parse('{"site": []}', "t") == []


# -- availability degradation (no image / no docker) -------------------------
@pytest.mark.parametrize("mod", [recon, web, dast])
def test_dynamic_tool_unavailable_without_image(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = mod.make_docker().run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


@pytest.mark.parametrize("mod", [recon, web, dast])
def test_dynamic_tool_unavailable_without_daemon(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = mod.make_docker()
    assert tool.available() is False
    result = tool.run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.UNAVAILABLE


# -- OK path via monkeypatched container run ---------------------------------
@pytest.mark.parametrize("mod,n", [(recon, 3), (web, 4), (dast, 3)])
def test_dynamic_tool_parses_when_image_present(monkeypatch, mod, n):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    fixture_text = mod._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, fixture_text, ""))
    result = mod.make_docker().run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == n
    assert result.metadata["image"] == mod.IMAGE
    assert all(c.source_engine == "dynamic" for c in result.candidates)


# -- ERROR path is caught, never raised --------------------------------------
@pytest.mark.parametrize("mod", [recon, web, dast])
def test_dynamic_tool_error_is_caught(monkeypatch, mod):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("container exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = mod.make_docker().run("http://127.0.0.1:8080")
    assert result.status == ToolStatus.ERROR
    assert "container exploded" in result.errors[0]


def test_fixture_parser_error_becomes_error_status(monkeypatch):
    # A malformed fixture (DTD-bearing XML) surfaces as ERROR, not a crash.
    tool = recon.make_fixture()
    monkeypatch.setattr(
        tool, "_parser",
        lambda raw, target: recon.parse('<!DOCTYPE x><nmaprun/>', target))
    result = tool.run("t")
    assert result.status == ToolStatus.ERROR
    assert result.errors


# -- registry registration ---------------------------------------------------
def test_dynamic_adapters_register_as_dynamic():
    reg = ToolRegistry()
    for mod in (recon, web, dast):
        reg.register(mod.make_fixture())
    assert set(reg.names()) == {"recon", "web", "dast"}
    assert len(reg.by_kind(ToolKind.DYNAMIC)) == 3
    assert reg.by_kind(ToolKind.STATIC) == []
    report = reg.status_report()
    assert report["recon"]["kind"] == "dynamic"
    result = reg.run("dast", "http://127.0.0.1:8080")
    assert result.status == ToolStatus.OK
