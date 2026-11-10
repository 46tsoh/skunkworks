"""The common Tool interface every capability implements.

See `docs/specs/tool-interface.md`. A ``Tool`` turns a heterogeneous capability
into one uniform ``run(target, **opts) -> ToolResult`` call that yields
``Candidate`` objects. Binary/Docker-backed tools degrade to a recorded
``UNAVAILABLE`` result when their dependency is absent instead of raising, and
every capability ships a ``FixtureTool`` (same parser, recorded output) so the
whole pipeline is testable with no binaries and no network.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional, Protocol, Sequence, runtime_checkable

from aegis.knowledge.models import Candidate
from aegis.tools.runtime import (
    docker_available,
    image_present,
    run_container,
)


class ToolKind(str, Enum):
    DYNAMIC = "dynamic"
    STATIC = "static"


class ToolStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class Artifact:
    kind: str
    path: Path
    label: str = ""
    media_type: str = ""
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "path": str(self.path), "label": self.label,
                "media_type": self.media_type, "metadata": self.metadata}


@dataclass
class ToolResult:
    tool: str
    status: ToolStatus
    candidates: list = field(default_factory=list)
    raw: str = ""
    artifacts: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    duration_ms: float = 0.0
    target: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.OK

    @property
    def ran(self) -> bool:
        return self.status in (ToolStatus.OK, ToolStatus.ERROR)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool, "status": self.status.value,
            "candidates": [{"id": c.id, "title": c.title, "cwe": c.cwe,
                            "component": c.component} for c in self.candidates],
            "candidate_count": len(self.candidates),
            "raw": self.raw[:4000],
            "artifacts": [a.as_dict() for a in self.artifacts],
            "errors": list(self.errors), "duration_ms": round(self.duration_ms, 2),
            "target": self.target, "metadata": self.metadata,
        }


# A parser turns a tool's native output text into Candidate objects.
Parser = Callable[[str, str], List[Candidate]]


# A scanner report far larger than this is treated as an error rather than
# read into memory (a defense against a planted oversize/endless file).
_MAX_REPORT_BYTES = 64 * 1024 * 1024


def _read_report_file(path: Path) -> str:
    """Read a tool's report file safely.

    The report lives in a scratch dir the scanning container writes to, so the
    read is hardened against a planted special file:

    * ``O_NOFOLLOW`` — a symlink at the report path is refused (no redirect to
      an arbitrary host file).
    * ``O_NONBLOCK`` — opening a FIFO/device returns immediately instead of
      hanging forever waiting for a writer (DoS); we then require a regular file
      via ``fstat`` and bail otherwise.
    * a size cap — a report over ``_MAX_REPORT_BYTES`` is rejected, not slurped.

    Any absence/irregularity/oversize yields ``""`` (parsed as "no findings").
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""  # missing, or a symlink (ELOOP) — refuse either way
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return ""  # FIFO/device/dir — refuse (open did not block: O_NONBLOCK)
        if st.st_size > _MAX_REPORT_BYTES:
            return ""
        chunks = []
        remaining = _MAX_REPORT_BYTES
        while remaining > 0:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                break  # EOF
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return ""
    finally:
        os.close(fd)


@runtime_checkable
class Tool(Protocol):
    name: str
    kind: ToolKind
    requires_binary: Optional[str]

    def available(self) -> bool: ...
    def run(self, target: str, **opts) -> ToolResult: ...


class FixtureTool:
    """Parses a recorded native-output file with the production parser.

    Default-registered variant: runs offline, deterministically, with the same
    parser the live adapter uses — so the parser (the bug-prone part) is covered
    without any binary present.
    """

    def __init__(self, name: str, kind: ToolKind, fixture_path, parser: Parser,
                 requires_binary: Optional[str] = None) -> None:
        self.name = name
        self.kind = kind
        self.fixture_path = Path(fixture_path)
        self._parser = parser
        self.requires_binary = requires_binary

    def available(self) -> bool:
        return self.fixture_path.exists()

    def run(self, target: str, **opts) -> ToolResult:
        t0 = time.perf_counter()
        if not self.available():
            return ToolResult(self.name, ToolStatus.UNAVAILABLE, target=target,
                              errors=[f"fixture {self.fixture_path} missing"])
        raw = self.fixture_path.read_text(encoding="utf-8")
        try:
            cands = self._parser(raw, target)
        except Exception as exc:  # parser bug surfaces as ERROR, not a crash
            return ToolResult(self.name, ToolStatus.ERROR, raw=raw, target=target,
                              errors=[f"parse error: {exc!r}"],
                              duration_ms=(time.perf_counter() - t0) * 1000.0)
        for c in cands:
            c.metadata.setdefault("tool", self.name)
        return ToolResult(self.name, ToolStatus.OK, candidates=cands, raw=raw,
                          target=target, metadata={"fixture": str(self.fixture_path)},
                          duration_ms=(time.perf_counter() - t0) * 1000.0)


class DockerBackedTool:
    """Base for adapters that run their binary in a **local** container.

    Subclasses set ``name``/``kind``/``image`` and implement ``argv(target)`` and
    ``parser``. ``available()`` is true only when Docker is up and the image is
    already present locally (no implicit pull). ``run()`` wraps execution so a
    missing image is ``UNAVAILABLE`` and any failure is ``ERROR`` — never a raise.
    """

    name: str = "docker-tool"
    kind: ToolKind = ToolKind.STATIC
    image: str = ""
    requires_binary = "docker"
    container_workdir = "/work"
    timeout_s = 120.0
    # Exit codes that mean "ran successfully". Default {0}; adapters whose tool
    # exits non-zero to signal findings (e.g. semgrep exits 1) widen this. A
    # non-zero exit outside this set is a real failure -> ERROR (never a silent
    # clean OK: a failed scan must not look like a finding-free scan).
    ok_exit_codes = frozenset({0})
    # Tools that read a mounted target (vs. a URL) set this so a missing/
    # unmountable target is ERROR rather than a meaningless empty scan.
    requires_target_mount = False
    # Only remote network scanners (recon/web/dast) may ever run with the
    # network enabled. Everything else — especially code-executing tools
    # (sandbox/shell/poc) — is refused a network grant so `aegis scan` can never
    # turn a local sandbox into a network-reaching one (isolation bypass).
    allows_network = False

    def __init__(self, parser: Parser) -> None:
        self._parser = parser

    def available(self) -> bool:
        return docker_available() and image_present(self.image)

    def argv(self, target: str, **opts) -> Sequence[str]:
        raise NotImplementedError

    def mounts(self, target: str):
        # Mount the local target read-only at the container workdir.
        p = Path(target)
        if p.exists():
            return [(str(p), self.container_workdir)]
        return []

    def volumes(self):
        # Named Docker volumes to mount read-only (e.g. provisioned scanner
        # templates). Default none; network scanners that need a data set
        # (nuclei templates) override this.
        return []

    def rw_volumes(self):
        # Named Docker volumes to mount read-WRITE, for a tool that reads a
        # provisioned data set and writes alongside it (e.g. Trivy's vuln DB +
        # its scan cache share one cache dir). Default none. Stays inside the
        # named volume — no host path is exposed, and the scan still runs with
        # the default --network none.
        return []

    def report_mount(self):
        # Some scanners cannot stream their machine-readable report to stdout
        # and must write it to a *file* (ZAP writes JSON under /zap/wrk). A tool
        # that returns ``(container_dir, filename)`` here gets a fresh, empty,
        # writable host dir mounted at ``container_dir``; ``argv()`` receives the
        # in-container report path as ``opts["report_path"]``, and ``run()``
        # parses the file's contents (not stdout) once the container exits.
        # Default None: the tool's report is on stdout.
        return None

    def run(self, target: str, *, network: str = "none", **opts) -> ToolResult:
        t0 = time.perf_counter()
        if not docker_available():
            return ToolResult(self.name, ToolStatus.UNAVAILABLE, target=target,
                              errors=["docker daemon not available"])
        if not image_present(self.image):
            return ToolResult(
                self.name, ToolStatus.UNAVAILABLE, target=target,
                errors=[f"image {self.image!r} not present; build/pull it "
                        "locally (see docker/README.md) or use the fixture"])
        # A network grant is only ever allowed for remote-scanner tools, and
        # never alongside a local mount (don't expose local files to a
        # network-reaching container).
        if network != "none":
            if not self.allows_network:
                return ToolResult(
                    self.name, ToolStatus.ERROR, target=target,
                    errors=[f"tool {self.name!r} is not a network scanner; "
                            "refusing a network grant (isolation)"],
                    duration_ms=(time.perf_counter() - t0) * 1000.0)
            if Path(target).exists():
                return ToolResult(
                    self.name, ToolStatus.ERROR, target=target,
                    errors=["refusing a network scan of a target that resolves "
                            "to a local path (ambiguous mount vs. host)"],
                    duration_ms=(time.perf_counter() - t0) * 1000.0)
            mounts = []  # never mount local files into a networked container
        else:
            mounts = self.mounts(target)
        if self.requires_target_mount and not mounts and network == "none":
            return ToolResult(
                self.name, ToolStatus.ERROR, target=target,
                errors=[f"target {target!r} not found / not mountable"],
                duration_ms=(time.perf_counter() - t0) * 1000.0)
        # A tool that writes its report to a file (not stdout) gets a fresh
        # writable host dir mounted at its report directory; we read the report
        # back from there and clean the dir up afterwards.
        report_spec = self.report_mount()
        rw_mounts = []
        report_dir = None
        report_parent = None
        if report_spec is not None:
            container_dir, filename = report_spec
            # The scanner may run as a non-root UID inside the container (ZAP is
            # uid 1000) and must be able to write the report, so the mount dir
            # is group/other-writable. To avoid a world-writable dir on a shared
            # host, it lives INSIDE a 0700 parent we own: directory traversal
            # needs execute on every ancestor, so no other local user can reach
            # the inner dir even at 0777. The Docker daemon (root) still resolves
            # the bind mount. We also refuse a symlinked report on read-back.
            report_parent = tempfile.mkdtemp(prefix="aegis-report-")  # 0700, ours
            report_dir = os.path.join(report_parent, "wrk")
            os.mkdir(report_dir, 0o777)
            rw_mounts = [(report_dir, container_dir)]
            opts = {**opts, "report_path": f"{container_dir}/{filename}"}
        try:
            cr = run_container(self.image, self.argv(target, **opts),
                               mounts=mounts, workdir=self.container_workdir,
                               timeout_s=self.timeout_s, network=network,
                               volumes=self.volumes(), rw_mounts=rw_mounts,
                               rw_volumes=self.rw_volumes())
            raw = cr.stdout + (("\n[stderr]\n" + cr.stderr) if cr.stderr else "")
            # Fail-closed: a timeout or an unexpected exit code is an ERROR, and
            # no candidates are surfaced from a failed run.
            if cr.timed_out:
                return ToolResult(self.name, ToolStatus.ERROR, raw=raw,
                                  target=target, errors=["timed out"],
                                  metadata={"image": self.image, "exit": cr.exit_code},
                                  duration_ms=(time.perf_counter() - t0) * 1000.0)
            if cr.exit_code not in self.ok_exit_codes:
                return ToolResult(
                    self.name, ToolStatus.ERROR, raw=raw, target=target,
                    errors=[f"exit code {cr.exit_code} (ok: "
                            f"{sorted(self.ok_exit_codes)})"],
                    metadata={"image": self.image, "exit": cr.exit_code},
                    duration_ms=(time.perf_counter() - t0) * 1000.0)
            # Parse the report file for file-emitting tools; stdout otherwise.
            if report_dir is not None:
                parse_input = _read_report_file(
                    Path(report_dir) / report_spec[1])
            else:
                parse_input = cr.stdout
            cands = self._parser(parse_input, target)
            for c in cands:
                c.metadata.setdefault("tool", self.name)
            return ToolResult(self.name, ToolStatus.OK, candidates=cands, raw=raw,
                              target=target,
                              metadata={"image": self.image, "exit": cr.exit_code},
                              duration_ms=(time.perf_counter() - t0) * 1000.0)
        except Exception as exc:
            return ToolResult(self.name, ToolStatus.ERROR, target=target,
                              errors=[f"{type(exc).__name__}: {exc}"],
                              duration_ms=(time.perf_counter() - t0) * 1000.0)
        finally:
            if report_parent is not None:
                shutil.rmtree(report_parent, ignore_errors=True)


class ToolRegistry:
    """Name -> Tool map the engines query."""

    def __init__(self) -> None:
        self._tools: dict = {}
        self._order: list = []

    def register(self, tool: Tool, replace: bool = False) -> None:
        if tool.name in self._tools and not replace:
            raise ValueError(f"tool {tool.name!r} already registered")
        if tool.name not in self._tools:
            self._order.append(tool.name)
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def names(self) -> list:
        return list(self._order)

    def by_kind(self, kind: ToolKind) -> list:
        return [self._tools[n] for n in self._order if self._tools[n].kind == kind]

    def available(self, kind: Optional[ToolKind] = None) -> list:
        out = []
        for n in self._order:
            t = self._tools[n]
            if kind is not None and t.kind != kind:
                continue
            if t.available():
                out.append(t)
        return out

    def run(self, name: str, target: str, **opts) -> ToolResult:
        return self._tools[name].run(target, **opts)

    def status_report(self) -> dict:
        return {n: {"kind": self._tools[n].kind.value,
                    "requires_binary": getattr(self._tools[n], "requires_binary", None),
                    "available": self._tools[n].available()}
                for n in self._order}


__all__ = [
    "ToolKind", "ToolStatus", "Artifact", "ToolResult", "Tool", "Parser",
    "FixtureTool", "DockerBackedTool", "ToolRegistry",
]
