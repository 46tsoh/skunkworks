"""Aegis tool/scanner adapters behind one common Tool interface."""

from aegis.tools.base import (
    Artifact,
    DockerBackedTool,
    FixtureTool,
    Tool,
    ToolKind,
    ToolRegistry,
    ToolResult,
    ToolStatus,
)
from aegis.tools.registry import ADAPTER_MODULES, default_registry
from aegis.tools.runtime import docker_available, image_present

__all__ = [
    "Artifact", "DockerBackedTool", "FixtureTool", "Tool", "ToolKind",
    "ToolRegistry", "ToolResult", "ToolStatus", "ADAPTER_MODULES",
    "default_registry", "docker_available", "image_present",
]
