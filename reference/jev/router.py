"""DecisionRouter: the single choke point for agent decisions.

Both Strix and RAPTOR should route their routing/triage/gate decisions through
one ``DecisionRouter`` instead of making ad-hoc model calls scattered through
the codebase. Centralizing them is what delivers the engineering wins:

* **Thresholds as config** — each decision *kind* has a tunable threshold,
  separate from the model, so you calibrate without touching agent logic.
* **Observability** — every decision is appended to a structured JSONL log
  (kind, inputs, outcome, probability, threshold, backend, latency, cache hit),
  giving an auditable, replayable trail of *why* the agent branched.
* **Caching** — identical decisions within a run are answered once.
* **Calibration hook** — ``record_outcome`` lets you feed ground truth
  (e.g. RAPTOR's labeled ``core/dataflow/corpus/``) back to measure and tune
  gate thresholds.

Standard library only.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence, Union

from .decision_client import (
    BooleanResult,
    ChoiceResult,
    DecisionClient,
    ScoreResult,
)


@dataclass
class RouterMetrics:
    calls: int = 0
    cache_hits: int = 0
    by_backend: dict = field(default_factory=dict)
    total_latency_ms: float = 0.0

    def record(self, backend: str, latency_ms: float, cache_hit: bool) -> None:
        self.calls += 1
        if cache_hit:
            self.cache_hits += 1
        self.by_backend[backend] = self.by_backend.get(backend, 0) + 1
        self.total_latency_ms += latency_ms


class DecisionRouter:
    """Thin, observable wrapper over :class:`DecisionClient`.

    Parameters
    ----------
    client:
        The underlying decision client (primary + fallback).
    thresholds:
        Per-kind boolean thresholds, e.g. ``{"triage_true_positive": 0.4}``.
        Lower threshold = keep more findings (safer against false negatives).
    log_path:
        If set, decisions are appended as JSON lines here.
    cache:
        Whether to memoize identical decisions for the router's lifetime.
    """

    def __init__(
        self,
        client: DecisionClient,
        thresholds: Optional[dict] = None,
        log_path: Optional[Union[str, Path]] = None,
        cache: bool = True,
        default_threshold: float = 0.5,
    ) -> None:
        self.client = client
        self.thresholds = dict(thresholds or {})
        self.default_threshold = default_threshold
        self.log_path = Path(log_path) if log_path else None
        self._cache_enabled = cache
        self._cache: dict = {}
        self._lock = threading.Lock()
        self.metrics = RouterMetrics()

    # -- public API -------------------------------------------------------- #
    def threshold_for(self, kind: str) -> float:
        return self.thresholds.get(kind, self.default_threshold)

    def choose(
        self, kind: str, prompt: str, options: Sequence[str]
    ) -> ChoiceResult:
        key = ("choose", kind, prompt, tuple(options))
        result, hit = self._cached(key, lambda: self.client.choose(prompt, options))
        self._log(kind, "choose", {"options": list(options)},
                  {"index": result.index, "option": result.option},
                  result.probability, None, result, hit)
        return result

    def score(
        self, kind: str, prompt: str, scale_min: float = 0.0,
        scale_max: float = 10.0,
    ) -> ScoreResult:
        key = ("score", kind, prompt, scale_min, scale_max)
        result, hit = self._cached(
            key, lambda: self.client.score(prompt, scale_min, scale_max)
        )
        self._log(kind, "score", {"scale": [scale_min, scale_max]},
                  {"value": result.value}, None, None, result, hit)
        return result

    def gate(self, kind: str, statement: str) -> bool:
        """Boolean decision resolved against the configured threshold.

        Returns a plain ``bool`` — this is what makes gated agent paths
        (Strix triage, RAPTOR ``/validate`` stages) directly assertable in
        tests.
        """
        key = ("boolean", kind, statement)
        result, hit = self._cached(key, lambda: self.client.boolean(statement))
        threshold = self.threshold_for(kind)
        decision = result.decide(threshold)
        self._log(kind, "gate", {"statement": statement},
                  {"decision": decision}, result.probability, threshold,
                  result, hit)
        return decision

    def record_outcome(self, kind: str, decided: bool, truth: bool) -> None:
        """Feed ground truth back for calibration/analysis.

        Writes a ``calibration`` record to the log; an offline tool can then
        compute per-kind precision/recall and recommend thresholds.
        """
        self._write_log(
            {
                "ts": time.time(),
                "type": "calibration",
                "kind": kind,
                "decided": decided,
                "truth": truth,
            }
        )

    # -- internals --------------------------------------------------------- #
    def _cached(self, key, compute):
        if self._cache_enabled:
            with self._lock:
                if key in self._cache:
                    return self._cache[key], True
        result = compute()
        if self._cache_enabled:
            with self._lock:
                self._cache[key] = result
        return result, False

    def _log(self, kind, op, inputs, outcome, probability, threshold, result,
             cache_hit) -> None:
        self.metrics.record(result.backend, result.latency_ms, cache_hit)
        self._write_log(
            {
                "ts": time.time(),
                "type": "decision",
                "kind": kind,
                "op": op,
                "inputs": inputs,
                "outcome": outcome,
                "probability": probability,
                "threshold": threshold,
                "backend": result.backend,
                "latency_ms": round(result.latency_ms, 2),
                "cache_hit": cache_hit,
            }
        )

    def _write_log(self, record: dict) -> None:
        if self.log_path is None:
            return
        line = json.dumps(record, default=str)
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
