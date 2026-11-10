"""Tests for the dynamic proxy and browser adapters (group: proxy-browser).

All offline: the Docker-backed path is exercised through availability checks and
a monkeypatched runtime, never by pulling images or touching the network.
"""

from aegis.tools.adapters import browser, proxy
from aegis.tools.base import ToolKind, ToolStatus
from aegis.tools.runtime import ContainerRun


# == proxy ===================================================================
def test_proxy_fixture_parses_candidates():
    tool = proxy.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.DYNAMIC
    result = tool.run("https://shop.example.com")
    assert result.status == ToolStatus.OK

    ids = {c.id for c in result.candidates}
    assert ids == {"proxy-1", "proxy-2", "proxy-3"}

    reflected = next(c for c in result.candidates if c.id == "proxy-1")
    assert reflected.cwe == "CWE-79"
    assert reflected.component == "https://shop.example.com/search"
    assert reflected.source_engine == "dynamic"
    assert reflected.metadata["tool"] == "proxy"
    assert reflected.metadata["param"] == "q"
    assert reflected.owasp.startswith("A03")  # CWE-79 -> injection

    header = next(c for c in result.candidates if c.id == "proxy-2")
    assert header.cwe == "CWE-693"
    assert "Content-Security-Policy" in header.title
    assert header.component == "https://shop.example.com/search"

    cors = next(c for c in result.candidates if c.id == "proxy-3")
    assert cors.cwe == "CWE-942"
    assert cors.component == "https://api.example.com/v1/profile"
    assert cors.metadata["with_credentials"] is True


def test_proxy_parse_handles_empty():
    assert proxy.parse("", "t") == []
    assert proxy.parse('{"log": {"entries": []}}', "t") == []


def test_proxy_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = proxy.make_docker().run("https://shop.example.com")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_proxy_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = proxy.make_docker()
    assert tool.available() is False
    assert tool.run("https://shop.example.com").status == ToolStatus.UNAVAILABLE


def test_proxy_ok_when_image_present(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    har = proxy._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, har, ""))
    result = proxy.make_docker().run("https://shop.example.com")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == proxy.IMAGE


def test_proxy_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("proxy exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = proxy.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "proxy exploded" in result.errors[0]


# == browser =================================================================
def test_browser_fixture_parses_candidates():
    tool = browser.make_fixture()
    assert tool.available()
    assert tool.kind == ToolKind.DYNAMIC
    result = tool.run("https://shop.example.com")
    assert result.status == ToolStatus.OK

    ids = {c.id for c in result.candidates}
    assert ids == {"browser-1", "browser-2", "browser-3"}

    dom = next(c for c in result.candidates if c.id == "browser-1")
    assert dom.cwe == "CWE-79"
    assert dom.component == "assets/app.js:120"
    assert dom.source_engine == "dynamic"
    assert dom.metadata["tool"] == "browser"
    assert any("screenshot" in e for e in dom.evidence)  # artifact reference carried

    mixed = next(c for c in result.candidates if c.id == "browser-2")
    assert mixed.cwe == "CWE-319"
    assert mixed.component == "https://shop.example.com/"

    secret = next(c for c in result.candidates if c.id == "browser-3")
    assert secret.cwe == "CWE-798"
    assert secret.component == "assets/config.js:8"
    assert secret.owasp.startswith("A07")  # CWE-798 -> auth failures
    # the real secret must not leak verbatim into evidence
    assert all("AKIAIOSFODNN7EXAMPLE" not in e for e in secret.evidence)


def test_browser_parse_handles_empty():
    assert browser.parse("", "t") == []
    assert browser.parse('{"pages": []}', "t") == []


def test_browser_unavailable_without_image(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: False)
    result = browser.make_docker().run("https://shop.example.com")
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.candidates == []
    assert result.errors and "image" in result.errors[0]


def test_browser_unavailable_without_daemon(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: False)
    tool = browser.make_docker()
    assert tool.available() is False
    assert tool.run("https://shop.example.com").status == ToolStatus.UNAVAILABLE


def test_browser_ok_when_image_present(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    navlog = browser._FIXTURE.read_text()
    monkeypatch.setattr(base, "run_container",
                        lambda *a, **k: ContainerRun(0, navlog, ""))
    result = browser.make_docker().run("https://shop.example.com")
    assert result.status == ToolStatus.OK
    assert len(result.candidates) == 3
    assert result.metadata["image"] == browser.IMAGE


def test_browser_error_is_caught(monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    def boom(*a, **k):
        raise RuntimeError("browser exploded")

    monkeypatch.setattr(base, "run_container", boom)
    result = browser.make_docker().run("t")
    assert result.status == ToolStatus.ERROR
    assert "browser exploded" in result.errors[0]
