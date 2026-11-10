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


def test_proxy_declares_report_mount():
    # mitmproxy can only emit HAR to a file in a mounted dir; the tool must ask
    # for a writable report mount so run() reads the HAR back (like ZAP).
    cdir, fname = proxy.make_docker().report_mount()
    assert cdir == "/aegis/out" and fname.endswith(".har")


def test_proxy_argv_replays_offline_to_report_file():
    # Live replay is network-free (-n: no proxy server) and writes HAR to the
    # mounted report path via the built-in hardump addon, not stdout.
    tool = proxy.make_docker()
    report = f"{tool.REPORT_DIR}/{tool.REPORT_FILE}"
    argv = tool.argv("x", report_path=report)
    assert argv[0] == "mitmdump"
    assert "-n" in argv          # no server started -> no network
    assert argv[argv.index("-r") + 1] == tool.INPUT_FLOW
    assert f"hardump={report}" in argv


def test_proxy_mounts_flow_read_only(tmp_path):
    # The recorded flow dump (the target) is mounted read-only at INPUT_FLOW.
    flow = tmp_path / "flows"
    flow.write_bytes(b"\x00recorded")
    tool = proxy.make_docker()
    assert tool.mounts(str(flow)) == [(str(flow), tool.INPUT_FLOW)]
    # a non-path target (bare URL) mounts nothing
    assert tool.mounts("https://shop.example.com") == []


def test_proxy_ok_reads_har_from_report_mount(monkeypatch):
    # The HAR is read back from the writable report mount, not stdout.
    import aegis.tools.base as base
    from pathlib import Path as _P
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    har = proxy._FIXTURE.read_text()
    spec = proxy.make_docker().report_mount()

    def fake_run(*a, **k):
        for host, _c in (k.get("rw_mounts") or []):
            (_P(host) / spec[1]).write_text(har, encoding="utf-8")
        return ContainerRun(0, "", "")  # nothing on stdout

    monkeypatch.setattr(base, "run_container", fake_run)
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


def test_browser_declares_report_mount():
    # The navigation log is produced as a file in a mounted dir; the tool must
    # ask for a writable report mount so run() reads it back (not stdout).
    cdir, fname = browser.make_docker().report_mount()
    assert cdir == "/aegis/out" and fname.endswith(".json")


def test_browser_argv_runs_driver_under_node_to_report_file(tmp_path):
    # The image's Chromium entrypoint is overridden to node so our driver runs;
    # it writes the navlog JSON to the mounted report file and keeps --no-sandbox.
    tool = browser.make_docker()
    assert tool.entrypoint == "node"   # Chromium entrypoint bypassed
    report = f"{tool.REPORT_DIR}/{tool.REPORT_FILE}"
    argv = tool.argv(str(tmp_path), report_path=report)
    assert argv[0] == tool.DRIVER_PATH
    assert argv[argv.index("--out") + 1] == report
    assert "--no-sandbox" in argv and "--disable-gpu" in argv
    # a local target is loaded as a file:// URL off the read-only site mount
    assert argv[argv.index("--target") + 1] == f"file://{tool.INPUT_DIR}/index.html"
    # an explicit reachable URL is honoured verbatim
    argv2 = tool.argv(str(tmp_path), url="https://live.example.com", report_path=report)
    assert argv2[argv2.index("--target") + 1] == "https://live.example.com"


def test_browser_mounts_driver_and_target_read_only(tmp_path):
    # The driver is always mounted read-only; a local target is mounted too.
    tool = browser.make_docker()
    assert tool.DRIVER_SRC.exists()  # driver ships in-repo
    site = tmp_path / "site"
    site.mkdir()
    mounts = tool.mounts(str(site))
    assert (str(tool.DRIVER_SRC), tool.DRIVER_PATH) in mounts
    assert (str(site), tool.INPUT_DIR) in mounts
    # a bare URL target mounts only the driver (no network grant is taken)
    assert tool.mounts("https://shop.example.com") == [
        (str(tool.DRIVER_SRC), tool.DRIVER_PATH)]


def test_browser_single_file_target_mounts_as_index(tmp_path):
    # A saved single page (a file, not a dir) must mount as index.html so the
    # driver's file://<INPUT_DIR>/index.html resolves — not bind the file over
    # the directory path (which would make the load fail).
    tool = browser.make_docker()
    page = tmp_path / "page.html"
    page.write_text("<html></html>", encoding="utf-8")
    mounts = tool.mounts(str(page))
    assert (str(page), f"{tool.INPUT_DIR}/index.html") in mounts
    assert (str(page), tool.INPUT_DIR) not in mounts
    # argv still loads the index.html path for a local target
    argv = tool.argv(str(page), report_path="/aegis/out/navlog.json")
    assert argv[argv.index("--target") + 1] == f"file://{tool.INPUT_DIR}/index.html"


def test_browser_ok_reads_navlog_from_report_mount(monkeypatch):
    # The navlog is read back from the writable report mount, not stdout.
    import aegis.tools.base as base
    from pathlib import Path as _P
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    navlog = browser._FIXTURE.read_text()
    spec = browser.make_docker().report_mount()

    def fake_run(*a, **k):
        for host, _c in (k.get("rw_mounts") or []):
            (_P(host) / spec[1]).write_text(navlog, encoding="utf-8")
        return ContainerRun(0, "", "")  # nothing on stdout

    monkeypatch.setattr(base, "run_container", fake_run)
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
