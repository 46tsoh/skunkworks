"""Tests for threshold calibration against the labeled corpus (offline)."""

import json

from aegis.calibration import (
    PointMetrics,
    calibrate,
    load_labeled_corpus,
    recommended_thresholds,
)
from aegis.cli import main

_CORPUS = "data/corpus/labeled.json"


def test_point_metrics_math():
    m = PointMetrics(threshold=0.5, tp=7, fp=1, tn=2, fn=0)
    assert m.recall == 1.0
    assert round(m.precision, 3) == 0.875
    assert round(m.f1, 3) == 0.933
    assert m.accuracy == round(9 / 10, 3) or abs(m.accuracy - 0.9) < 1e-9


def test_corpus_loads_with_labels():
    corpus = load_labeled_corpus(_CORPUS)
    assert len(corpus) == 10
    cand, labels = corpus[0]
    assert cand.id == "L01"
    assert labels["true_positive"] is True


def test_triage_separates_true_from_false_positives():
    report = calibrate(_CORPUS)
    tri = report.kinds["triage.true_positive"]
    best = tri.best_f1()
    # The labeled corpus is cleanly separable -> a perfect operating point.
    assert best.f1 == 1.0
    assert best.recall == 1.0
    # recommended recall-first threshold sits in the separating gap.
    assert 0.3 < tri.recommended_recall_first <= 0.7


def test_posterior_calibration_reaches_full_recall():
    report = calibrate(_CORPUS)
    post = report.kinds["hypothesis.posterior"]
    rf = post.at(post.recommended_recall_first)
    assert rf.recall == 1.0
    assert rf.fp == 0  # full recall with no false positives on this corpus


def test_recommended_thresholds_shape():
    report = calibrate(_CORPUS)
    rec = recommended_thresholds(report, recall_first=True)
    assert set(rec) == {"triage.true_positive", "hypothesis.posterior"}
    assert all(0.0 <= v <= 1.0 for v in rec.values())


def test_sweep_is_monotone_endpoints():
    report = calibrate(_CORPUS)
    tri = report.kinds["triage.true_positive"]
    at0 = tri.at(0.0)
    at1 = tri.at(1.0)
    # threshold 0 accepts everything (no false negatives); threshold 1 rejects
    # (hint probs are < 1.0) so no true positives survive.
    assert at0.fn == 0
    assert at1.tp == 0


def test_cli_calibrate_writes_report(tmp_path):
    out = tmp_path / "cal.json"
    rc = main(["calibrate", "--out", str(out)])
    assert rc == 0
    report = json.loads(out.read_text())
    assert report["corpus_size"] == 10
    assert "triage.true_positive" in report["kinds"]
