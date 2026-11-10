"""Threshold calibration against a labeled corpus.

RAPTOR calibrates its gates on a labeled regression corpus; Aegis does the same
through the decision layer. Given a corpus of candidates with ground-truth
labels, this measures, per decision kind, how the backend's probability/score
separates true findings from false ones — then recommends a threshold.

Two recommendations are produced per kind:

* **max-F1** — the threshold that best balances precision and recall.
* **recall-first** — the lowest threshold that still reaches a target recall
  (default 1.0). In security triage a missed real vulnerability (false
  negative) is worse than a wasted review, so this is usually the one to ship.

Fully offline with the ``static`` backend (probabilities come from the corpus
``hints``); a localhost model backend can be calibrated the same way.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from aegis.analysis.triage import triage_statement
from aegis.config import AegisConfig
from aegis.decision import DecisionClient, StaticBackend
from aegis.knowledge.models import Candidate


@dataclass
class PointMetrics:
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    def as_dict(self) -> dict:
        return {"threshold": round(self.threshold, 3), "tp": self.tp,
                "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": round(self.precision, 3),
                "recall": round(self.recall, 3), "f1": round(self.f1, 3),
                "accuracy": round(self.accuracy, 3)}


@dataclass
class KindCalibration:
    kind: str
    sweep: List[PointMetrics]
    recommended_f1: float
    recommended_recall_first: float
    target_recall: float

    def best_f1(self) -> PointMetrics:
        return max(self.sweep, key=lambda m: (m.f1, m.precision))

    def at(self, threshold: float) -> PointMetrics:
        return min(self.sweep, key=lambda m: abs(m.threshold - threshold))

    def as_dict(self) -> dict:
        return {"kind": self.kind,
                "recommended_f1": round(self.recommended_f1, 3),
                "recommended_recall_first": round(self.recommended_recall_first, 3),
                "target_recall": self.target_recall,
                "best_f1": self.best_f1().as_dict(),
                "at_recommended_recall_first":
                    self.at(self.recommended_recall_first).as_dict(),
                "sweep": [m.as_dict() for m in self.sweep]}


@dataclass
class CalibrationReport:
    backend: str
    corpus_size: int
    kinds: dict = field(default_factory=dict)  # kind -> KindCalibration

    def as_dict(self) -> dict:
        return {"backend": self.backend, "corpus_size": self.corpus_size,
                "kinds": {k: v.as_dict() for k, v in self.kinds.items()}}


def load_labeled_corpus(path) -> List[Tuple[Candidate, dict]]:
    """Load ``[{...candidate fields..., "labels": {...}}]`` into (Candidate, labels)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    fields = {"id", "title", "cwe", "component", "cvss_vector", "description",
              "evidence", "hints", "source_engine", "metadata"}
    out = []
    for item in data:
        labels = item.get("labels", {})
        known = {k: v for k, v in item.items() if k in fields}
        out.append((Candidate(**known), labels))
    return out


def _sweep(scored: Sequence[Tuple[float, bool]],
           target_recall: float = 1.0,
           steps: int = 101) -> KindCalibration:
    sweep: List[PointMetrics] = []
    for i in range(steps):
        th = i / (steps - 1)
        tp = fp = tn = fn = 0
        for prob, truth in scored:
            decided = prob >= th
            if decided and truth:
                tp += 1
            elif decided and not truth:
                fp += 1
            elif not decided and truth:
                fn += 1
            else:
                tn += 1
        sweep.append(PointMetrics(th, tp, fp, tn, fn))
    best_f1 = max(sweep, key=lambda m: (m.f1, m.precision))
    # recall-first: lowest threshold still meeting target recall, highest
    # precision among those (fewest false positives at full recall).
    meeting = [m for m in sweep if m.recall >= target_recall]
    if meeting:
        rec = max(meeting, key=lambda m: (m.precision, m.threshold))
    else:
        rec = best_f1
    return KindCalibration("", sweep, best_f1.threshold, rec.threshold,
                           target_recall)


def calibrate(corpus_path, backend: str = "static",
              target_recall: float = 1.0) -> CalibrationReport:
    """Measure triage and hypothesis separation on a labeled corpus.

    Both decision kinds estimate "is this a genuine vulnerability", so both are
    scored against the ``true_positive`` label. Returns a
    :class:`CalibrationReport` with per-kind sweeps and recommended thresholds.
    """
    corpus = load_labeled_corpus(corpus_path)
    # The static backend resolves each statement's [ref=id] from the candidate's
    # hints — the offline, deterministic oracle. (A localhost model backend is
    # calibrated identically by swapping the client.)
    if backend != "static":
        raise ValueError("calibrate() currently supports the offline 'static' "
                         "backend; point it at recorded probabilities otherwise")
    from aegis.analysis.backends import HintBackend
    client = DecisionClient(primary=HintBackend([c for c, _ in corpus]))

    triage_scored: List[Tuple[float, bool]] = []
    posterior_scored: List[Tuple[float, bool]] = []
    for cand, labels in corpus:
        truth = bool(labels.get("true_positive"))
        triage_scored.append(
            (client.boolean(triage_statement(cand)).probability, truth))
        stmt = (f"Hypothesis: '{cand.title}' is a genuine vulnerability. "
                f"[ref={cand.id}]")
        posterior_scored.append((client.score(stmt, 0.0, 1.0).value, truth))

    report = CalibrationReport(backend=backend, corpus_size=len(corpus))
    for kind, scored in (("triage.true_positive", triage_scored),
                         ("hypothesis.posterior", posterior_scored)):
        kc = _sweep(scored, target_recall=target_recall)
        kc.kind = kind
        report.kinds[kind] = kc
    return report


def recommended_thresholds(report: CalibrationReport,
                           recall_first: bool = True) -> dict:
    """Extract a thresholds dict (kind -> value) ready for AegisConfig."""
    return {k: (v.recommended_recall_first if recall_first else v.recommended_f1)
            for k, v in report.kinds.items()}


__all__ = [
    "PointMetrics", "KindCalibration", "CalibrationReport",
    "load_labeled_corpus", "calibrate", "recommended_thresholds",
]
