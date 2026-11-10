"""Tests for the Docker/host runtime and registry wiring (no real docker)."""

import os
import subprocess

import pytest

import aegis.tools.runtime as rt
from aegis.tools.base import ToolKind, ToolStatus


@pytest.fixture(autouse=True)
def _clear_docker_cache():
    rt.docker_available.cache_clear()
    yield
    rt.docker_available.cache_clear()


def test_run_container_builds_local_only_argv(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "out", "")

    monkeypatch.setattr(rt.subprocess, "run", fake_run)
    cr = rt.run_container("img:1", ["scan", "/work"],
                          mounts=[("/tmp/x", "/work")])
    assert cr.exit_code == 0 and cr.stdout == "out"
    cmd = captured["cmd"]
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network=none" in cmd
    assert "--pull=never" in cmd  # never pulls at scan time
    assert any(part.endswith(":/work:ro") for part in cmd)  # read-only mount
    assert cmd[-2:] == ["scan", "/work"]


def test_run_container_mounts_named_volume(monkeypatch):
    captured = {}
    monkeypatch.setattr(rt.subprocess, "run",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd)
                                          or subprocess.CompletedProcess(cmd, 0, "", "")))
    rt.run_container("img:1", ["scan"], network="bridge",
                     volumes=[("aegis-nuclei-templates", "/root/nuclei-templates")])
    # a named volume is mounted read-only (no host-path resolution)
    assert "-v" in captured["cmd"]
    assert "aegis-nuclei-templates:/root/nuclei-templates:ro" in captured["cmd"]


def test_run_container_rw_named_volume_is_writable(monkeypatch):
    captured = {}
    monkeypatch.setattr(rt.subprocess, "run",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd)
                                          or subprocess.CompletedProcess(cmd, 0, "", "")))
    rt.run_container("img:1", ["fs"], network="none",
                     rw_volumes=[("aegis-trivy-cache", "/root/.cache/trivy")])
    cmd = captured["cmd"]
    # writable named volume → no :ro suffix (unlike the read-only `volumes`)
    assert "aegis-trivy-cache:/root/.cache/trivy" in cmd
    assert "aegis-trivy-cache:/root/.cache/trivy:ro" not in cmd


def test_web_tool_declares_templates_volume():
    from aegis.tools.adapters.web import make_docker
    assert make_docker().volumes() == [
        ("aegis-nuclei-templates", "/root/nuclei-templates")]


def test_run_container_rw_mount_is_writable(monkeypatch):
    captured = {}
    monkeypatch.setattr(rt.subprocess, "run",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd)
                                          or subprocess.CompletedProcess(cmd, 0, "", "")))
    rt.run_container("img:1", ["scan"], network="bridge",
                     rw_mounts=[("/tmp/out", "/zap/wrk")])
    cmd = captured["cmd"]
    # a writable mount has NO :ro suffix (unlike every read-only mount)
    assert any(p.endswith(":/zap/wrk") for p in cmd)
    assert not any(p.endswith(":/zap/wrk:ro") for p in cmd)


def test_report_emitting_tool_reads_file_and_cleans_up(monkeypatch, tmp_path):
    """A tool whose report_mount() is set parses the report FILE (not stdout)
    and removes its scratch dir afterwards."""
    import aegis.tools.base as base
    from aegis.knowledge.models import Candidate

    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)

    seen = {}

    class ReportTool(base.DockerBackedTool):
        name, kind, image = "rep", ToolKind.DYNAMIC, "img:1"
        allows_network = True

        def report_mount(self):
            return ("/out", "r.json")

        def argv(self, target, **opts):
            seen["report_path"] = opts.get("report_path")
            return ["scan"]

    def fake_run(image, args, **k):
        host, container = k["rw_mounts"][0]
        seen["host"] = host
        # the real tool writes its report into the mounted dir
        (__import__("pathlib").Path(host) / "r.json").write_text('{"x": 1}')
        return rt.ContainerRun(0, "stdout-ignored", "")

    monkeypatch.setattr(base, "run_container", fake_run)
    tool = ReportTool(parser=lambda raw, t: (
        [Candidate(id="c1", title=raw.strip(), cwe="CWE-20",
                   component=t, cvss_vector="")] if raw.strip() else []))
    result = tool.run("http://t", network="bridge")

    assert result.status == ToolStatus.OK
    assert result.candidates and result.candidates[0].title == '{"x": 1}'
    assert seen["report_path"] == "/out/r.json"   # argv got the in-container path
    import os
    assert not os.path.exists(seen["host"])        # scratch dir cleaned up


def test_read_report_refuses_symlink(tmp_path):
    """The report read-back must not follow a symlink (no arbitrary-file read
    if an attacker plants one at the report path)."""
    import aegis.tools.base as base
    secret = tmp_path / "secret"
    secret.write_text("TOP SECRET")
    link = tmp_path / "report.json"
    os.symlink(secret, link)
    assert base._read_report_file(link) == ""          # symlink refused
    # a real regular file is read normally
    real = tmp_path / "real.json"
    real.write_text('{"ok": 1}')
    assert base._read_report_file(real) == '{"ok": 1}'
    assert base._read_report_file(tmp_path / "missing.json") == ""


def test_read_report_refuses_fifo_without_hanging(tmp_path):
    """A planted FIFO must not hang the open (O_NONBLOCK) and must be refused
    as a non-regular file — no reader/writer deadlock DoS."""
    import aegis.tools.base as base
    fifo = tmp_path / "report.json"
    os.mkfifo(fifo)
    # With no writer attached, a blocking open would hang forever; this returns.
    assert base._read_report_file(fifo) == ""


def test_read_report_rejects_oversize(tmp_path, monkeypatch):
    import aegis.tools.base as base
    monkeypatch.setattr(base, "_MAX_REPORT_BYTES", 8)
    big = tmp_path / "big.json"
    big.write_text("x" * 64)
    assert base._read_report_file(big) == ""          # over the cap → refused
    ok = tmp_path / "ok.json"
    ok.write_text("tiny")
    assert base._read_report_file(ok) == "tiny"


def test_report_scratch_dir_shielded_by_private_parent(monkeypatch):
    """The writable mount dir lives inside a 0700 parent we own, so no other
    local user can traverse into it even though it is group/other-writable."""
    import os as _os
    import stat as _stat
    import aegis.tools.base as base
    from aegis.knowledge.models import Candidate

    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    captured = {}

    class ReportTool(base.DockerBackedTool):
        name, kind, image = "rep", ToolKind.DYNAMIC, "img:1"
        allows_network = True
        def report_mount(self):
            return ("/out", "r.json")
        def argv(self, target, **opts):
            return ["scan"]

    def fake_run(image, args, **k):
        host, _ = k["rw_mounts"][0]
        parent = _os.path.dirname(host)
        captured["parent_mode"] = _stat.S_IMODE(_os.stat(parent).st_mode)
        (__import__("pathlib").Path(host) / "r.json").write_text('{"x":1}')
        return rt.ContainerRun(0, "", "")

    monkeypatch.setattr(base, "run_container", fake_run)
    tool = ReportTool(parser=lambda raw, t: (
        [Candidate(id="c1", title=raw.strip(), cwe="CWE-20",
                   component=t, cvss_vector="")] if raw.strip() else []))
    result = tool.run("http://t", network="bridge")
    assert result.status == ToolStatus.OK and result.candidates
    assert captured["parent_mode"] == 0o700     # private parent shields the mount


def test_run_container_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)
    monkeypatch.setattr(rt.subprocess, "run", boom)
    cr = rt.run_container("img", ["x"])
    assert cr.timed_out and cr.exit_code == 124


def test_run_local_success_and_failure(monkeypatch):
    monkeypatch.setattr(rt.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, "ok", ""))
    assert rt.run_local(["echo", "ok"]).stdout == "ok"

    def enoent(*a, **k):
        raise FileNotFoundError("no such binary")
    monkeypatch.setattr(rt.subprocess, "run", enoent)
    cr = rt.run_local(["nope"])
    assert cr.exit_code == 127 and "no such binary" in cr.stderr


def test_docker_available_false_without_cli(monkeypatch):
    monkeypatch.setattr(rt.shutil, "which", lambda name: None)
    assert rt.docker_available() is False


def test_docker_available_true_when_info_ok(monkeypatch):
    monkeypatch.setattr(rt.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(rt.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    assert rt.docker_available() is True


def test_image_present_false_when_docker_absent(monkeypatch):
    monkeypatch.setattr(rt.shutil, "which", lambda name: None)
    assert rt.image_present("anything") is False


def test_default_registry_prefers_live_docker_tool(monkeypatch):
    # When docker + image are present, the live Docker adapter takes the slot.
    import aegis.tools.base as base
    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(base, "image_present", lambda image: True)
    from aegis.tools.registry import default_registry
    reg = default_registry(prefer_docker=True)
    semgrep_tool = reg.get("semgrep")
    assert semgrep_tool.__class__.__name__.endswith("DockerTool")
    assert reg.get("semgrep").kind == ToolKind.STATIC
