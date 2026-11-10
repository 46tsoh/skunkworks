"""Local Docker runtime for tool adapters.

Binary-backed tools run inside **local** containers, never on the host and never
with network access. Every container is launched with ``--network none`` (no
egress — the local-only guarantee), ``--rm``, read-only target mounts, and
CPU/memory/time caps. If Docker or the image is absent, callers degrade to a
clear ``UNAVAILABLE`` result (see :mod:`aegis.tools.base`); nothing here raises
for a missing daemon.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


@lru_cache(maxsize=1)
def docker_available() -> bool:
    """True if the Docker CLI exists and the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True,
                           timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def image_present(image: str) -> bool:
    """True if ``image`` is already pulled locally (no network probe)."""
    if not docker_available():
        return False
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


@dataclass
class ContainerRun:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_container(
    image: str,
    args: Sequence[str],
    mounts: Optional[Sequence[Tuple[str, str]]] = None,  # (host, container) read-only
    workdir: str = "/work",
    network: str = "none",
    timeout_s: float = 120.0,
    memory: str = "2g",
    cpus: str = "2.0",
    entrypoint: Optional[str] = None,
    volumes: Optional[Sequence[Tuple[str, str]]] = None,  # (named volume, container) ro
    rw_mounts: Optional[Sequence[Tuple[str, str]]] = None,  # (host, container) read-WRITE
    rw_volumes: Optional[Sequence[Tuple[str, str]]] = None,  # (named volume, container) rw
) -> ContainerRun:
    """Run ``image`` locally with the given args and return its output.

    Local-only by construction: ``--network none`` unless a caller explicitly
    overrides ``network`` (no adapter should). Mounts are read-only.
    """
    # --pull=never: a scan must never pull an image (that would touch the
    # network). Images are fetched ahead of time via docker/pull-images.sh;
    # adapters check image_present() before calling this.
    cmd: List[str] = ["docker", "run", "--rm", "--pull=never",
                      f"--network={network}", f"--memory={memory}",
                      f"--cpus={cpus}"]
    if entrypoint is not None:
        cmd += ["--entrypoint", entrypoint]
    for host, container in (mounts or []):
        cmd += ["-v", f"{Path(host).resolve()}:{container}:ro"]
    for name, container in (volumes or []):
        # A named Docker volume (not a host path) — e.g. provisioned scanner
        # templates. Read-only like every other mount.
        cmd += ["-v", f"{name}:{container}:ro"]
    for host, container in (rw_mounts or []):
        # A writable scratch mount for tools that can only emit their machine
        # report as a *file* (e.g. ZAP writes JSON to /zap/wrk). The caller owns
        # a fresh, empty host dir; nothing sensitive is ever mounted this way.
        cmd += ["-v", f"{Path(host).resolve()}:{container}"]
    for name, container in (rw_volumes or []):
        # A writable *named* Docker volume (not a host path) for a tool that
        # must read AND write a provisioned data set — e.g. Trivy reads its vuln
        # DB and writes its scan cache into the same cache dir. The data stays
        # inside the named volume; no host path is exposed.
        cmd += ["-v", f"{name}:{container}"]
    cmd += ["-w", workdir, image, *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        return ContainerRun(r.returncode, r.stdout, r.stderr)
    except subprocess.TimeoutExpired as exc:
        return ContainerRun(124, exc.stdout or "", exc.stderr or "", timed_out=True)


def run_local(
    args: Sequence[str],
    timeout_s: float = 60.0,
    cwd: Optional[str] = None,
    input_text: Optional[str] = None,
) -> ContainerRun:
    """Run a pure-local host subprocess (for tools that need no container).

    Used by host-only adapters (e.g. git-history forensics on the local clone,
    the resource-capped Python sandbox). No network isolation is enforced here;
    adapters that need isolation use :func:`run_container`.
    """
    try:
        r = subprocess.run(list(args), capture_output=True, text=True,
                           timeout=timeout_s, cwd=cwd, input=input_text)
        return ContainerRun(r.returncode, r.stdout, r.stderr)
    except subprocess.TimeoutExpired as exc:
        return ContainerRun(124, exc.stdout or "", exc.stderr or "", timed_out=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return ContainerRun(127, "", str(exc))


__all__ = [
    "docker_available", "image_present", "run_container", "run_local",
    "ContainerRun",
]
