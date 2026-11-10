"""Tests for the static-scanner adapters: codeql (SARIF) and sca (Trivy).

All offline: the Docker-backed path is exercised through availability checks and
a monkeypatched runtime, never by pulling an image or opening a socket. The same
parse() covers both the fixture and the live path, so the bug-prone parser is
pinned without any binary present.
"""

import pytest

from aegis.tools.adapters import codeql, sca
from aegis.tools.base import ToolKind, ToolStatus


# =========================================================================
# codeql (CWE from dataflow queries; SARIF 2.1.0)
# =========================================================================
def test_codeql_fixture_parses_candidates():
    tool = codeql.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.STATIC
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"codeql-1", "codeql-2"}

    sqli = next(c for c in result.candidates if c.id == "codeql-1")
    assert sqli.cwe == "CWE-89"  # zero-padded external/cwe/cwe-089 normalised
    assert sqli.component == "app/dao/users.py:57"
    assert sqli.source_engine == "static"
    assert sqli.metadata["tool"] == "codeql"
    assert sqli.owasp.startswith("A03")  # CWE-89 -> injection
    # dataflow + SMT path-feasibility provenance survives into the candidate
    assert sqli.metadata["dataflow_steps"] == 2
    assert sqli.metadata["path_feasible"] is True
    assert any("SMT path-feasibility" in e for e in sqli.evidence)

    traversal = next(c for c in result.candidates if c.id == "codeql-2")
    assert traversal.cwe == "CWE-22"  # cwe-022 normalised
    assert traversal.component == "app/files/download.py:33"
    assert traversal.owasp.startswith("A01")  # path traversal -> access control


def test_codeql_parse_handles_empty():
    assert codeql.parse("", "t") == []
    assert codeql.parse('{"runs": []}', "t") == []
    assert codeql.parse('{"runs": [{"tool": {"driver": {}}, "results": []}]}', "t") == []


def test_codeql_argv_bypasses_entrypoint_and_uses_bundled_suite():
    """CodeQL overrides the image's broken setup.py entrypoint, builds a DB,
    analyzes with a full-path bundled suite (offline, no pack download), and
    emits SARIF on stdout for the parser."""
    tool = codeql.make_docker()
    assert tool.entrypoint == "bash"   # the image's setup.py shim is bypassed
    argv = tool.argv("/work", language="python")
    assert argv[0] == "-lc"
    script = argv[1]
    assert "codeql database create" in script
    assert "codeql database analyze" in script
    # suite resolved by full path inside the bundled repo (no network pack fetch)
    assert tool.REPO_DIR in script and "python-security-extended.qls" in script
    assert script.rstrip().endswith("sarif")  # cat the SARIF to stdout


def test_codeql_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = codeql.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_codeql_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = codeql.make_docker()
    assert tool.available() is False
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE


def test_codeql_parses_when_image_present(monkeypatch):
    import aegis.tools.base as base
    from aegis.tools.runtime import ContainerRun
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    sarif = codeql._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, sarif, ""))
    result = codeql.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 2
    assert result.metadata["image"] == codeql.IMAGE


def test_codeql_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("codeql exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = codeql.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "codeql exploded" in result.errors[0]


# =========================================================================
# sca (vulnerable/outdated dependencies; Trivy fs JSON)
# =========================================================================
def test_sca_fixture_parses_candidates():
    tool = sca.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.STATIC
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.OK
    ids = {c.id for c in result.candidates}
    assert ids == {"sca-1", "sca-2", "sca-3"}

    # Every SCA hit is the vulnerable/outdated-component class -> OWASP A06.
    for c in result.candidates:
        assert c.cwe == "CWE-1104"
        assert c.owasp.startswith("A06")
        assert c.source_engine == "static"
        assert c.metadata["tool"] == "sca"

    first = next(c for c in result.candidates if c.id == "sca-1")
    assert first.component == "lodash@4.17.20"
    assert first.metadata["cve"] == "CVE-2021-23337"
    assert first.metadata["fixed_version"] == "4.17.21"
    assert first.metadata["advisory_cwes"] == ["CWE-77"]

    # CRITICAL severity -> critical default CVSS vector (C:H/I:H/A:H).
    crit = next(c for c in result.candidates if c.id == "sca-3")
    assert crit.component == "urllib3@1.24.1"
    assert "C:H/I:H/A:H" in crit.cvss_vector


def test_sca_parse_handles_empty_and_null_vulns():
    assert sca.parse("", "t") == []
    assert sca.parse('{"Results": []}', "t") == []
    # a Results entry with null Vulnerabilities must not crash or emit anything
    assert sca.parse('{"Results": [{"Target": "go.sum", "Vulnerabilities": null}]}', "t") == []


def test_sca_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = sca.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_sca_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = sca.make_docker()
    assert tool.available() is False
    result = tool.run("data/sample_target")
    assert result.status == ToolStatus.UNAVAILABLE


def test_sca_parses_when_image_present(monkeypatch):
    import aegis.tools.base as base
    from aegis.tools.runtime import ContainerRun
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    trivy_json = sca._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, trivy_json, ""))
    result = sca.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == sca.IMAGE


def test_sca_argv_is_offline_and_uses_cache_volume():
    """The sca scan must never touch the network: it skips the DB update, scans
    offline, and reads the DB from the provisioned cache volume."""
    tool = sca.make_docker()
    argv = tool.argv("data/sample_target")
    assert argv[0] == "fs"
    assert "--skip-db-update" in argv and "--offline-scan" in argv
    assert argv[argv.index("--cache-dir") + 1] == tool.CACHE_DIR
    # the cache volume is mounted read-WRITE (Trivy writes its scan cache there)
    assert tool.rw_volumes() == [(tool.CACHE_VOLUME, tool.CACHE_DIR)]
    assert tool.volumes() == []  # not a read-only data volume


def test_sca_cache_volume_mounted_writable(monkeypatch):
    """run() must pass the sca cache as a read-WRITE named volume."""
    import aegis.tools.base as base
    from aegis.tools.runtime import ContainerRun
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    captured = {}

    def fake_run(*a, **k):
        captured.update(k)
        return ContainerRun(0, sca._FIXTURE.read_text(), "")

    monkeypatch.setattr(base, "run_container", fake_run)
    result = sca.make_docker().run("data/sample_target")
    assert result.status == ToolStatus.OK
    assert captured["rw_volumes"] == [("aegis-trivy-cache", "/root/.cache/trivy")]


def test_sca_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("trivy exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = sca.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "trivy exploded" in result.errors[0]
