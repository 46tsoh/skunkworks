"""Central configuration for Aegis — thresholds, backend selection, env.

One place owns the knobs that both engines (dynamic + static) share:

* which decision backend answers (``static`` offline / ``basal`` localhost /
  ``jev`` remote),
* the per-decision-kind thresholds and the hypothesis posterior floor,
* where the decision log is written,
* the ``local_only`` guard that enforces the "nothing leaves localhost"
  operating constraint by refusing the remote Jev backend.

Environment variables (all optional) let a run be configured without code:

* ``AEGIS_BACKEND``        — ``static`` | ``basal`` | ``jev``
* ``AEGIS_POSTERIOR_MIN``  — float, hypothesis posterior floor
* ``AEGIS_LOG``            — path for the decisions JSONL log
* ``AEGIS_LOCAL_ONLY``     — ``0`` to allow the remote Jev backend
* ``AEGIS_THRESHOLD_<KIND>`` — override one threshold, e.g.
  ``AEGIS_THRESHOLD_TRIAGE_TRUE_POSITIVE=0.5`` sets ``triage.true_positive``
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Default per-decision thresholds shared by the analysis pipeline. Triage is
# low (keep unless clearly a false positive); dedup is higher (collapse only on
# a confident match).
DEFAULT_THRESHOLDS = {
    "triage.true_positive": 0.4,
    "dedupe.same_vuln": 0.6,
    "validate.stage": 0.5,
}
DEFAULT_POSTERIOR_MIN = 0.5

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val in _TRUE:
        return True
    if val in _FALSE:
        return False
    return default


@dataclass
class AegisConfig:
    """Resolved run configuration for a single Aegis invocation."""

    backend: str = "static"
    thresholds: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    posterior_min: float = DEFAULT_POSTERIOR_MIN
    default_threshold: float = 0.5
    log_path: Optional[Path] = None
    local_only: bool = True

    def __post_init__(self) -> None:
        if self.backend not in ("static", "basal", "jev"):
            raise ValueError(
                f"unknown backend {self.backend!r} (static|basal|jev)"
            )
        if self.local_only and self.backend == "jev":
            raise ValueError(
                "backend 'jev' is a remote (api.typesafe.ai) decision service; "
                "Aegis runs local_only by default. Use 'static' (offline) or "
                "'basal' (localhost), or set local_only=False / "
                "AEGIS_LOCAL_ONLY=0 to explicitly allow egress."
            )
        if self.log_path is not None and not isinstance(self.log_path, Path):
            self.log_path = Path(self.log_path)

    @classmethod
    def from_env(cls, **overrides) -> "AegisConfig":
        """Build config from environment, with explicit keyword overrides.

        Keyword ``overrides`` win over environment values, which win over
        defaults.
        """
        thresholds = dict(DEFAULT_THRESHOLDS)
        for key, raw in os.environ.items():
            if not key.startswith("AEGIS_THRESHOLD_"):
                continue
            kind = key[len("AEGIS_THRESHOLD_"):].lower().replace("_", ".", 1)
            try:
                thresholds[kind] = float(raw)
            except ValueError:
                continue

        log = os.environ.get("AEGIS_LOG")
        resolved = dict(
            backend=os.environ.get("AEGIS_BACKEND", "static"),
            thresholds=thresholds,
            posterior_min=float(
                os.environ.get("AEGIS_POSTERIOR_MIN", DEFAULT_POSTERIOR_MIN)
            ),
            log_path=Path(log) if log else None,
            local_only=_env_bool("AEGIS_LOCAL_ONLY", True),
        )
        resolved.update(overrides)
        return cls(**resolved)


__all__ = [
    "AegisConfig",
    "DEFAULT_THRESHOLDS",
    "DEFAULT_POSTERIOR_MIN",
]
