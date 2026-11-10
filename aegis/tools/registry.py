"""Build the standard tool registry (fixture-first, Docker when available).

Each adapter module exposes ``make_fixture()`` and ``make_docker()``. A fixture
adapter is registered for every capability so a fresh checkout is fully
exercisable offline; the Docker-backed adapter replaces it under the same name
only when it is actually runnable locally (daemon up + image present). So the
engines always have a runnable tool, and live tools take over transparently
once their image is built.
"""

from __future__ import annotations

import importlib
from typing import List, Optional

from aegis.tools.base import ToolKind, ToolRegistry

# Adapter modules under aegis.tools.adapters. Extended as capabilities land.
ADAPTER_MODULES: List[str] = [
    "semgrep",
]


def default_registry(config=None, prefer_docker: bool = True) -> ToolRegistry:
    reg = ToolRegistry()
    for mod_name in ADAPTER_MODULES:
        try:
            mod = importlib.import_module(f"aegis.tools.adapters.{mod_name}")
        except Exception:  # a broken adapter never breaks the whole registry
            continue
        fixture = mod.make_fixture() if hasattr(mod, "make_fixture") else None
        docker = mod.make_docker() if (prefer_docker and hasattr(mod, "make_docker")) else None
        if docker is not None and docker.available():
            reg.register(docker, replace=True)
            if fixture is not None and not reg_has(reg, fixture.name):
                pass
        elif fixture is not None:
            reg.register(fixture, replace=True)
        elif docker is not None:
            reg.register(docker, replace=True)
    return reg


def reg_has(reg: ToolRegistry, name: str) -> bool:
    return name in reg.names()


__all__ = ["ADAPTER_MODULES", "default_registry"]
