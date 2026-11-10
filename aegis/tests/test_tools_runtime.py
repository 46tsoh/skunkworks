"""Tests for the Docker/host runtime and registry wiring (no real docker)."""

import subprocess

import pytest

import aegis.tools.runtime as rt
from aegis.tools.base import ToolKind


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
